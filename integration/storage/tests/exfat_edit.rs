use partmgr::{
    fs_core::{Budget, Cancellation, FileRead, NativeName, Resources},
    fs_exfat_audit::{ExfatAuditLimits, audit_exfat},
    fs_exfat_edit::{ExfatEditBinding, ExfatEditLimits, ExfatEditRegion, ExfatEditor},
    fs_exfat_volume::{ExfatReadLimits, ExfatVolume},
    fs_storage::SectorGeometry,
    fs_undo::UndoLimits,
    storage::{FileStorage, Storage},
};
use partmgr_storage_integration::WriterSession;
use std::sync::Arc;
use virtdisk::{DiskView, Image, ImageFormat, ImageWriter, ReadAt};
#[path = "fixtures/exfat_edit.rs"]
mod fixture;
const BASE: usize = 8192;
const VOLUME: usize = 2 << 20;
const DISK: usize = 4 << 20;
fn read_limits() -> ExfatReadLimits {
    ExfatReadLimits {
        max_chain_clusters: 512,
        max_directory_slots: 128,
        max_upcase_bytes: 131072,
    }
}
fn audit_limits() -> ExfatAuditLimits {
    ExfatAuditLimits {
        clusters: 4096,
        entries: 64,
        directory_slots: 1024,
        work: 20000,
        findings: 32,
    }
}
fn round_trip(format: ImageFormat, directory: tempfile::TempDir) -> (tempfile::TempDir, Vec<u8>) {
    let path = directory.path().join("disk.img");
    let journal_path = directory.path().join("external-undo.raw");
    std::fs::write(&journal_path, vec![0; 131072]).unwrap();
    let mut expected = vec![0; DISK];
    expected[..BASE].fill(0xa5);
    expected[BASE..BASE + VOLUME].copy_from_slice(&fixture::fixture());
    expected[BASE + VOLUME..].fill(0x5a);
    let writer = ImageWriter::create(&path, format, DISK as u64).unwrap();
    let mut initial =
        WriterSession::new(writer, 0, DISK as u64, SectorGeometry::default()).unwrap();
    assert_eq!(initial.write_at(0, &expected).unwrap(), DISK);
    initial.flush().unwrap();
    drop(initial);
    let session = WriterSession::new(
        ImageWriter::open(&path, format).unwrap(),
        BASE as u64,
        VOLUME as u64,
        SectorGeometry::default(),
    )
    .unwrap();
    let r = Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    };
    let mut editor = ExfatEditor::open(
        FailedBarrier {
            inner: session,
            fail: true,
        },
        FileStorage::open(&journal_path).unwrap(),
        ExfatEditRegion {
            offset: 0,
            length: VOLUME as u64,
        },
        ExfatEditBinding {
            volume: [0x43; 32],
            generation: 19,
        },
        ExfatEditLimits {
            read: read_limits(),
            audit: audit_limits(),
            affected_bytes: 8192,
            work: 20000,
            undo: UndoLimits {
                patches: 128,
                body_bytes: 131072,
            },
        },
        &r,
    )
    .unwrap();
    let native: Vec<u16> = "prefixNoChain.bin".encode_utf16().collect();
    let names = [NativeName::Utf16(native.clone())];
    let mut payload: Vec<_> = (0..600).map(|i| ((i * 17 + 3) % 251) as u8).collect();
    payload.resize(700, 0);
    let old = editor.open_file(&names, &r).unwrap();
    let failed = editor
        .plan_replace(&old, 0, b"rejected commit", &r)
        .unwrap();
    let failure = editor.commit(failed, [0x71; 16], &r).unwrap_err();
    assert!(failure.source.source.is_some());
    assert_eq!(
        editor.state(),
        partmgr::fs_exfat_edit::ExfatEditState::NeedsRecovery
    );
    assert!(editor.read_at(&old, 0, &mut [0], &r).is_err());
    editor.recover(&r).unwrap();
    assert_eq!(
        editor.state(),
        partmgr::fs_exfat_edit::ExfatEditState::Ready
    );
    let restored = editor.open_file(&names, &r).unwrap();
    let mut restored_bytes = vec![0; payload.len()];
    assert_eq!(
        editor
            .read_at(&restored, 0, &mut restored_bytes, &r)
            .unwrap(),
        payload.len()
    );
    assert_eq!(restored_bytes, payload);
    drop(restored);
    drop(old);
    drop(failure);
    for operation in 0..3 {
        assert!(ImageWriter::open(&path, format).is_err());
        assert!(FileStorage::open(&journal_path).is_err());
        let old = editor.open_file(&names, &r).unwrap();
        let batch = match operation {
            0 => {
                payload[590..670].fill(0x31);
                editor.plan_replace(&old, 590, &[0x31; 80], &r).unwrap()
            }
            1 => {
                payload.resize(1900, 0);
                editor.plan_resize(&old, 1900, &r).unwrap()
            }
            _ => {
                payload.truncate(513);
                editor.plan_resize(&old, 513, &r).unwrap()
            }
        };
        for patch in batch.patches() {
            let at = BASE + patch.offset() as usize;
            assert_eq!(&expected[at..at + patch.expected().len()], patch.expected());
            expected[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
        }
        editor.commit(batch, [operation as u8 + 1; 16], &r).unwrap();
        assert!(editor.read_at(&old, 0, &mut [0], &r).is_err());
        let current = editor.open_file(&names, &r).unwrap();
        let mut actual = vec![0; payload.len()];
        assert_eq!(
            editor.read_at(&current, 0, &mut actual, &r).unwrap(),
            payload.len()
        );
        assert_eq!(actual, payload);
    }
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    let image: Arc<dyn ReadAt> = Arc::new(Image::open(&path, Some(format)).unwrap());
    let mut actual = vec![0; DISK];
    image.read_exact_at(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    let source: Arc<dyn ReadAt> =
        Arc::new(DiskView::new(image, BASE as u64, VOLUME as u64).unwrap());
    let audit = audit_exfat(source.clone(), read_limits(), audit_limits(), &r).unwrap();
    assert!(audit.namespace_complete() && audit.findings().is_empty());
    drop(audit);
    let volume = ExfatVolume::open(source, read_limits(), &r).unwrap();
    let root = volume.root_directory(&r).unwrap();
    let entry = root.lookup(&native).unwrap().unwrap();
    let file = volume.open_file(entry, &r).unwrap();
    let mut actual = vec![0; payload.len()];
    assert_eq!(file.read_at(0, &mut actual, &r).unwrap(), payload.len());
    assert_eq!(actual, payload);
    drop(file);
    drop(root);
    drop(volume);
    assert_eq!(r.memory.used(), 0);
    (directory, expected)
}
#[test]
fn raw_bounded_exfat_replace_extend_truncate_reopen_and_framing() {
    round_trip(ImageFormat::Raw, tempfile::tempdir().unwrap());
}
#[test]
#[cfg(target_os = "linux")]
fn qcow2_bounded_exfat_replace_extend_truncate_reopen_and_framing() {
    round_trip(ImageFormat::Qcow2, tempfile::tempdir().unwrap());
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "explicit qemu-img oracle requires fresh PARTMGR_EXFAT_CONTAINER_EVIDENCE"]
fn independent_qcow2_conversion_after_exfat_replace_extend_truncate() {
    use std::{path::PathBuf, process::Command};
    let root = PathBuf::from(
        std::env::var_os("PARTMGR_EXFAT_CONTAINER_EVIDENCE")
            .expect("explicit evidence path required"),
    );
    std::fs::create_dir(&root).expect("fresh evidence directory required");
    let mut receipt = String::from(
        "profile=exfat-qcow2-owned-recovery-replace-extend-truncate\nscope=independent container oracle; not native filesystem, firmware or hardware power-loss evidence\n",
    );
    let tool = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join("qemu-img"))
        .find(|p| p.is_file())
        .expect("qemu-img required");
    let run = |label: &str, args: &[&std::ffi::OsStr]| {
        let out = Command::new(&tool)
            .args(args)
            .output()
            .expect("enabled gate requires qemu-img");
        std::fs::write(root.join(format!("{label}.stdout")), &out.stdout).unwrap();
        std::fs::write(root.join(format!("{label}.stderr")), &out.stderr).unwrap();
        std::fs::write(
            root.join(format!("{label}.command.txt")),
            format!("program={tool:?}\nargs={args:?}\nstatus={}\n", out.status),
        )
        .unwrap();
        assert!(
            out.status.success(),
            "qemu-img {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };
    let binary = std::env::current_exe().unwrap();
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let test = manifest.join("tests/exfat_edit.rs");
    assert_eq!(
        std::fs::read(&test).unwrap(),
        include_bytes!("exfat_edit.rs")
    );
    let hash = |p: &std::path::Path| {
        let out = Command::new("sha256sum")
            .arg(p)
            .output()
            .expect("sha256sum required");
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let mut paths = vec![tool.clone(), binary, test, manifest.join("Cargo.lock")];
    for name in [
        "src/fs_exfat_volume.rs",
        "src/fs_exfat_audit.rs",
        "src/fs_exfat_edit.rs",
        "src/fs_exfat_edit_namespace.rs",
        "src/fs_undo.rs",
    ] {
        paths.push(manifest.join("../..").join(name));
    }
    let before: Vec<_> = paths.iter().map(|p| hash(p)).collect();
    let version = run("version", &[std::ffi::OsStr::new("--version")]);
    receipt.push_str(&String::from_utf8(version.stdout).unwrap());
    for h in &before {
        receipt.push_str(h);
    }
    let dir = tempfile::Builder::new()
        .prefix("exfat-qcow2-")
        .tempdir_in(&root)
        .unwrap();
    let (dir, expected) = round_trip(ImageFormat::Qcow2, dir);
    let disk = dir.path().join("disk.img");
    let raw = dir.path().join("converted.raw");
    let disk_hash = hash(&disk);
    let check = run(
        "check",
        &[
            std::ffi::OsStr::new("check"),
            std::ffi::OsStr::new("-f"),
            std::ffi::OsStr::new("qcow2"),
            disk.as_os_str(),
        ],
    );
    receipt.push_str(&format!(
        "qemu_check={}\n",
        String::from_utf8_lossy(&check.stdout)
    ));
    run(
        "convert",
        &[
            std::ffi::OsStr::new("convert"),
            std::ffi::OsStr::new("-f"),
            std::ffi::OsStr::new("qcow2"),
            std::ffi::OsStr::new("-O"),
            std::ffi::OsStr::new("raw"),
            disk.as_os_str(),
            raw.as_os_str(),
        ],
    );
    assert_eq!(std::fs::read(&raw).unwrap(), expected);
    assert_eq!(hash(&disk), disk_hash);
    for (p, h) in paths.iter().zip(&before) {
        assert_eq!(&hash(p), h);
    }
    receipt.push_str(&format!("converted={}status=passed\nwhole_logical_image=match\ncontainer_unchanged_by_oracle=passed\nsource_tool_binary_revalidation=passed\n",hash(&raw)));
    let kept = dir.keep();
    receipt.push_str(&format!("artifacts={}\n", kept.display()));
    std::fs::write(root.join("receipt.txt"), receipt).unwrap();
}

struct FailedBarrier {
    inner: WriterSession,
    fail: bool,
}
impl Storage for FailedBarrier {
    fn len(&self) -> std::io::Result<u64> {
        self.inner.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.inner.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> std::io::Result<usize> {
        self.inner.write_at(at, bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()?;
        if std::mem::take(&mut self.fail) {
            return Err(std::io::Error::other(
                "injected failure after actual container barrier",
            ));
        }
        Ok(())
    }
}
