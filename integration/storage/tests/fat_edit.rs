use partmgr::{
    fs_core::{Budget, Cancellation, FileRead, NativeName, Resources},
    fs_fat::FatVolume,
    fs_fat_audit::{FatAuditLimits, audit_fat},
    fs_fat_edit::{FatEditBinding, FatEditLimits, FatEditRegion, FatEditor, FatReplacement},
    fs_storage::SectorGeometry,
    fs_undo::UndoLimits,
    storage::{FileStorage, Storage},
};
use partmgr_storage_integration::WriterSession;
use std::sync::Arc;
use virtdisk::{DiskView, Image, ImageFormat, ImageWriter, ReadAt};

const BASE: usize = 8192;
const VOLUME: usize = 65536;
const DISK: usize = 2 << 20;
fn word(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn fixture() -> Vec<u8> {
    // Independent packed FAT12 layout: fragmented chain 2 -> 4 -> 3.
    let mut bytes = vec![0; VOLUME];
    bytes[..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
    word(&mut bytes, 11, 512);
    bytes[13] = 1;
    word(&mut bytes, 14, 1);
    bytes[16] = 1;
    word(&mut bytes, 17, 16);
    word(&mut bytes, 19, 128);
    bytes[21] = 0xf8;
    word(&mut bytes, 22, 1);
    word(&mut bytes, 510, 0xaa55);
    for (cluster, value) in [(0, 0xff8), (1, 0xfff), (2, 4), (4, 3), (3, 0xfff)] {
        let at = 512 + cluster * 3 / 2;
        let old = u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        word(
            &mut bytes,
            at,
            if cluster % 2 == 0 {
                (old & 0xf000) | value
            } else {
                (old & 0x000f) | (value << 4)
            },
        );
    }
    bytes[1024..1035].copy_from_slice(b"PAYLOAD BIN");
    bytes[1035] = 0x20;
    word(&mut bytes, 1050, 2);
    bytes[1052..1056].copy_from_slice(&1300u32.to_le_bytes());
    for (logical, cluster) in [2, 4, 3].into_iter().enumerate() {
        let physical = 1536 + (cluster - 2) * 512;
        bytes[physical..physical + 512].fill(0xa7);
        for i in 0..(1300 - logical * 512).min(512) {
            bytes[physical + i] = ((logical * 512 + i) % 251) as u8;
        }
    }
    bytes
}
fn audit_limits() -> FatAuditLimits {
    FatAuditLimits {
        clusters: 256,
        entries: 16,
        directory_slots: 64,
        findings: 16,
    }
}
fn round_trip(format: ImageFormat, directory: tempfile::TempDir) -> (tempfile::TempDir, Vec<u8>) {
    let path = directory.path().join("disk.img");
    let journal_path = directory.path().join("external-undo.raw");
    std::fs::write(&journal_path, vec![0; 65536]).unwrap();
    let mut expected = vec![0; DISK];
    expected[..BASE].fill(0xa5);
    expected[BASE..BASE + VOLUME].copy_from_slice(&fixture());
    expected[BASE + VOLUME..].fill(0x5a);
    let writer = ImageWriter::create(&path, format, DISK as u64).unwrap();
    let mut initial =
        WriterSession::new(writer, 0, DISK as u64, SectorGeometry::default()).unwrap();
    assert_eq!(initial.write_at(0, &expected).unwrap(), DISK);
    initial.flush().unwrap();
    drop(initial);
    let writer = ImageWriter::open(&path, format).unwrap();
    let session = WriterSession::new(
        writer,
        BASE as u64,
        VOLUME as u64,
        SectorGeometry::default(),
    )
    .unwrap();
    let r = Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    };
    let mut editor = FatEditor::open(
        session,
        FileStorage::open(&journal_path).unwrap(),
        FatEditRegion {
            offset: 0,
            length: VOLUME as u64,
        },
        FatEditBinding {
            volume: [0x42; 32],
            generation: 19,
        },
        FatEditLimits {
            audit: audit_limits(),
            file_clusters: 64,
            affected_bytes: 8192,
            replacements: 8,
            work: 4096,
            undo: UndoLimits {
                patches: 128,
                body_bytes: 65536,
            },
        },
        &r,
    )
    .unwrap();
    let names = [NativeName::Bytes(b"PAYLOAD BIN".to_vec())];
    let mut payload: Vec<_> = (0..1300).map(|i| (i % 251) as u8).collect();
    for operation in 0..3 {
        assert!(ImageWriter::open(&path, format).is_err());
        assert!(FileStorage::open(&journal_path).is_err());
        let old = editor.open_file(&names, &r).unwrap();
        let batch = match operation {
            0 => {
                payload[490..570].fill(0x31);
                editor
                    .plan_batch(
                        &[FatReplacement {
                            file: &old,
                            offset: 490,
                            bytes: &[0x31; 80],
                        }],
                        &r,
                    )
                    .unwrap()
            }
            1 => {
                payload.extend([0x72; 700]);
                editor.plan_extend_bytes(&old, &[0x72; 700], &r).unwrap()
            }
            _ => {
                payload.truncate(513);
                editor.plan_truncate(&old, 513, &r).unwrap()
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
        let mut bytes = vec![0; payload.len()];
        assert_eq!(
            editor.read_at(&current, 0, &mut bytes, &r).unwrap(),
            payload.len()
        );
        assert_eq!(bytes, payload);
    }
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    let image: Arc<dyn ReadAt> = Arc::new(Image::open(&path, Some(format)).unwrap());
    let mut actual = vec![0; DISK];
    image.read_exact_at(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    let source: Arc<dyn ReadAt> =
        Arc::new(DiskView::new(image, BASE as u64, VOLUME as u64).unwrap());
    let audit = audit_fat(source.clone(), audit_limits(), &r).unwrap();
    assert!(audit.namespace_complete() && audit.findings().is_empty());
    drop(audit);
    let volume = FatVolume::open(source).unwrap();
    let root = volume.root_directory(64, 64, &r).unwrap();
    let entry = root.lookup(&names[0]).unwrap().unwrap();
    let file = volume.open_entry(entry, 64, &r).unwrap();
    let mut bytes = vec![0; payload.len()];
    assert_eq!(file.read_at(0, &mut bytes, &r).unwrap(), payload.len());
    assert_eq!(bytes, payload);
    drop(file);
    drop(root);
    drop(volume);
    assert_eq!(r.memory.used(), 0);
    (directory, expected)
}
#[test]
fn raw_bounded_fat_replace_extend_truncate_reopen_and_framing() {
    round_trip(ImageFormat::Raw, tempfile::tempdir().unwrap());
}
#[test]
#[cfg(target_os = "linux")]
fn qcow2_bounded_fat_replace_extend_truncate_reopen_and_framing() {
    round_trip(ImageFormat::Qcow2, tempfile::tempdir().unwrap());
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "explicit qemu-img oracle requires PARTMGR_FAT_CONTAINER_EVIDENCE"]
fn independent_qcow2_conversion_after_fat_replace_extend_truncate() {
    use std::{ffi::OsStr, path::Path, process::Command};
    let base = std::env::var_os("PARTMGR_FAT_CONTAINER_EVIDENCE")
        .expect("PARTMGR_FAT_CONTAINER_EVIDENCE is required");
    std::fs::create_dir_all(&base).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("fat-qcow2-")
        .tempdir_in(base)
        .unwrap();
    let mut receipt = String::from(
        "profile=owned-bounded-fat12-qcow2-replace-extend-truncate-v1\nstatus=running\nscope=independent container conversion; no filesystem native oracle, power-loss or firmware claim\n",
    );
    fn run(program: &str, args: &[&OsStr], receipt: &mut String) {
        let mut command = Command::new(program);
        command.args(args);
        let output = command
            .output()
            .unwrap_or_else(|e| panic!("{command:?}: {e}"));
        receipt.push_str(&format!(
            "command={command:?}\nexit={}\nstdout={}\nstderr={}\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
        assert!(output.status.success(), "{receipt}");
    }
    for tool in ["qemu-img", "sha256sum"] {
        run(tool, &[OsStr::new("--version")], &mut receipt);
        let path = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|dir| dir.join(tool))
            .find(|p| p.is_file())
            .unwrap();
        run("sha256sum", &[path.as_os_str()], &mut receipt);
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["Cargo.toml", "Cargo.lock", "tests/fat_edit.rs"] {
        run(
            "sha256sum",
            &[manifest.join(name).as_os_str()],
            &mut receipt,
        );
    }
    let root = manifest.join("../..");
    for name in [
        "src/fs_fat_edit.rs",
        "src/fs_fat_edit_resize.rs",
        "src/fs_fat.rs",
        "src/fs_fat_audit.rs",
        "src/fs_undo.rs",
        "src/fs_storage.rs",
        "Cargo.toml",
        "Cargo.lock",
    ] {
        run("sha256sum", &[root.join(name).as_os_str()], &mut receipt);
    }
    run(
        "sha256sum",
        &[std::env::current_exe().unwrap().as_os_str()],
        &mut receipt,
    );
    let (directory, expected) = round_trip(ImageFormat::Qcow2, directory);
    let image = directory.path().join("disk.img");
    let before = std::fs::read(&image).unwrap();
    run(
        "qemu-img",
        &[
            OsStr::new("check"),
            OsStr::new("-f"),
            OsStr::new("qcow2"),
            image.as_os_str(),
        ],
        &mut receipt,
    );
    let converted = directory.path().join("independent.raw");
    run(
        "qemu-img",
        &[
            OsStr::new("convert"),
            OsStr::new("-f"),
            OsStr::new("qcow2"),
            OsStr::new("-O"),
            OsStr::new("raw"),
            image.as_os_str(),
            converted.as_os_str(),
        ],
        &mut receipt,
    );
    assert_eq!(std::fs::read(&converted).unwrap(), expected);
    assert_eq!(std::fs::read(&image).unwrap(), before);
    run(
        "sha256sum",
        &[image.as_os_str(), converted.as_os_str()],
        &mut receipt,
    );
    receipt.push_str("operations=replace,extend,truncate\nwhole_logical_disk=exact_reviewed_patch_match\nframing=unchanged\nwriter_and_journal_locks=retained\nreopened_allocation_audit=clean\nsource_unchanged_by_oracle=true\nstatus=passed\n");
    let retained = directory.keep();
    let record = retained.join("evidence.txt");
    std::fs::write(&record, receipt).unwrap();
    std::fs::File::open(&record).unwrap().sync_all().unwrap();
    std::fs::File::open(&retained).unwrap().sync_all().unwrap();
    eprintln!("native FAT container receipt={}", record.display());
}
