use partmgr::{fs_storage::SectorGeometry, storage::Storage};
use partmgr_storage_integration::WriterSession;
use virtdisk::{Image, ImageFormat, ImageWriter, InspectImage, ReadAt};

fn round_trip(format: ImageFormat) {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("disk.img");
    let writer = ImageWriter::create(&path, format, 2 << 20).unwrap();
    let expected = writer.inspection().geometry;
    let mut session = WriterSession::new(writer, 8192, 4096, SectorGeometry::default()).unwrap();
    assert_eq!(session.geometry().logical, expected.logical_sector_size);
    assert_eq!(session.geometry().physical, expected.physical_sector_size);
    assert_eq!(session.len().unwrap(), 4096);
    assert!(ImageWriter::open(&path, format).is_err());
    assert!(session.write_at(4090, &[9; 7]).is_err());
    assert!(session.write_at(u64::MAX, &[9]).is_err());
    assert!(session.zero(4090, 7).is_err());
    assert!(!session.mutation_uncertain());
    assert_eq!(session.write_at(17, &[0x5a; 1024]).unwrap(), 1024);
    let mut out = [0; 1024];
    session.read_exact_at(17, &mut out).unwrap();
    assert_eq!(out, [0x5a; 1024]);
    session.zero(512, 100).unwrap();
    session.flush().unwrap();
    assert!(!session.mutation_uncertain());
    drop(session);
    let reopened = Image::open(&path, Some(format)).unwrap();
    let mut whole = vec![0; 2 << 20];
    reopened.read_exact_at(0, &mut whole).unwrap();
    let mut expected = vec![0; 2 << 20];
    expected[8192 + 17..8192 + 17 + 1024].fill(0x5a);
    expected[8192 + 512..8192 + 612].fill(0);
    assert_eq!(whole, expected);
}
#[test]
fn raw_retained_lock_bounds_unknown_geometry_and_reopened_payload() {
    round_trip(ImageFormat::Raw);
}
#[test]
#[cfg(target_os = "linux")]
fn qcow2_retained_lock_bounds_and_reopened_payload() {
    round_trip(ImageFormat::Qcow2);
}
#[test]
fn invalid_region_or_explicit_geometry_rejects_without_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("disk.raw");
    let writer = ImageWriter::create(&path, ImageFormat::Raw, 8192).unwrap();
    assert!(WriterSession::new(writer, u64::MAX, 1, SectorGeometry::default()).is_err());
    let writer = ImageWriter::open(&path, ImageFormat::Raw).unwrap();
    assert!(
        WriterSession::new(
            writer,
            0,
            512,
            SectorGeometry {
                logical: Some(0),
                physical: None
            }
        )
        .is_err()
    );
    let writer = ImageWriter::open(&path, ImageFormat::Raw).unwrap();
    let session = WriterSession::new(
        writer,
        0,
        512,
        SectorGeometry {
            logical: Some(512),
            physical: Some(4096),
        },
    )
    .unwrap();
    assert_eq!(
        session.geometry(),
        SectorGeometry {
            logical: Some(512),
            physical: Some(4096)
        }
    );
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "explicit native bridge gate requires qemu-img, sha256sum and PARTMGR_STORAGE_EVIDENCE"]
fn independent_qcow2_conversion_after_bounded_session_flush() {
    use std::{ffi::OsStr, path::Path, process::Command};
    let base = std::env::var_os("PARTMGR_STORAGE_EVIDENCE")
        .expect("native bridge gate requires PARTMGR_STORAGE_EVIDENCE");
    std::fs::create_dir_all(&base).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("writer-bridge-")
        .tempdir_in(&base)
        .unwrap();
    let mut receipt = String::from(
        "profile=bounded-qcow2-writer-v1\nstatus=running\nlogical_bytes=2097152\nregion_offset=8192\nregion_bytes=4096\n",
    );
    fn run(program: &str, arguments: &[&OsStr], receipt: &mut String) {
        let mut command = Command::new(program);
        command.args(arguments);
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
    run("qemu-img", &[OsStr::new("--version")], &mut receipt);
    run("sha256sum", &[OsStr::new("--version")], &mut receipt);
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in ["Cargo.toml", "Cargo.lock", "src/lib.rs", "tests/session.rs"] {
        run(
            "sha256sum",
            &[manifest.join(relative).as_os_str()],
            &mut receipt,
        );
    }
    run(
        "sha256sum",
        &[std::env::current_exe().unwrap().as_os_str()],
        &mut receipt,
    );
    for tool in ["qemu-img", "sha256sum"] {
        let path = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|directory| directory.join(tool))
            .find(|path| path.is_file())
            .unwrap();
        run("sha256sum", &[path.as_os_str()], &mut receipt);
    }
    let image = directory.path().join("bounded.qcow2");
    let writer = ImageWriter::create(&image, ImageFormat::Qcow2, 2 << 20).unwrap();
    let mut session = WriterSession::new(writer, 8192, 4096, SectorGeometry::default()).unwrap();
    assert_eq!(session.write_at(17, &[0x5a; 1024]).unwrap(), 1024);
    session.zero(512, 100).unwrap();
    session.flush().unwrap();
    drop(session);
    let bytes_before = std::fs::read(&image).unwrap();
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
    let raw = directory.path().join("independent.raw");
    run(
        "qemu-img",
        &[
            OsStr::new("convert"),
            OsStr::new("-f"),
            OsStr::new("qcow2"),
            OsStr::new("-O"),
            OsStr::new("raw"),
            image.as_os_str(),
            raw.as_os_str(),
        ],
        &mut receipt,
    );
    let mut expected = vec![0; 2 << 20];
    expected[8192 + 17..8192 + 1041].fill(0x5a);
    expected[8192 + 512..8192 + 612].fill(0);
    assert_eq!(std::fs::read(&raw).unwrap(), expected);
    assert_eq!(std::fs::read(&image).unwrap(), bytes_before);
    run(
        "sha256sum",
        &[image.as_os_str(), raw.as_os_str()],
        &mut receipt,
    );
    receipt.push_str("independent_check=passed\nwhole_logical_payload=exact_match\nsource_unchanged=true\nstatus=passed\n");
    let retained = directory.keep();
    let record = retained.join("evidence.txt");
    std::fs::write(&record, receipt).unwrap();
    std::fs::File::open(&record).unwrap().sync_all().unwrap();
    std::fs::File::open(&retained).unwrap().sync_all().unwrap();
    eprintln!("native writer bridge receipt={}", record.display());
}
