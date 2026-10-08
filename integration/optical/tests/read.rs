use partmgr::fs_core::{Budget, Cancellation, ErrorKind, Resources};
use partmgr_optical::read::{OpticalReadIndex, OpticalReadLimits, SourceAdapter};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use virtdisk::{RawDisk, ReadAt};
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
#[test]
fn source_length_changes_are_detected_even_at_eof_or_for_empty_reads() {
    struct Changing {
        length: AtomicU64,
        calls: AtomicU64,
    }
    impl ReadAt for Changing {
        fn len(&self) -> u64 {
            self.length.load(Ordering::Acquire)
        }
        fn read_exact_at(&self, _: u64, out: &mut [u8]) -> io::Result<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            out.fill(9);
            Ok(())
        }
    }
    let source = Arc::new(Changing {
        length: AtomicU64::new(16),
        calls: AtomicU64::new(0),
    });
    let r = resources();
    let adapter = SourceAdapter::new(source.clone(), r.clone(), 1024);
    let mut buffer = [0u8; 4];
    assert_eq!(
        libmkiso::source::ReadAt::read_at(&adapter, 14, &mut buffer).unwrap(),
        2
    );
    assert_eq!(adapter.requested_bytes(), 2);
    let calls = source.calls.load(Ordering::Relaxed);
    source.length.store(17, Ordering::Release);
    for offset in [0, 16, 17, u64::MAX] {
        for out in [&mut buffer[..], &mut [][..]] {
            let error = libmkiso::source::ReadAt::read_at(&adapter, offset, out).unwrap_err();
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<partmgr::fs_core::Error>()
                    .unwrap()
                    .kind,
                ErrorKind::StalePlan
            );
        }
    }
    assert_eq!(source.calls.load(Ordering::Relaxed), calls);
    assert_eq!(adapter.requested_bytes(), 2);
    assert_eq!(r.memory.used(), 0);
}
fn limits() -> OpticalReadLimits {
    OpticalReadLimits {
        max_entries: 64,
        max_metadata_bytes: 256 * 1024,
        max_extents: 256,
        max_depth: 16,
    }
}
struct Region {
    bytes: Vec<u8>,
    start: usize,
    length: usize,
    fail: Arc<AtomicBool>,
}
impl ReadAt for Region {
    fn len(&self) -> u64 {
        self.length as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        if self.fail.load(Ordering::Acquire) {
            return Err(io::Error::other("injected contextual source failure"));
        }
        let offset =
            usize::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let end = offset
            .checked_add(out.len())
            .filter(|end| *end <= self.length)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(&self.bytes[self.start + offset..self.start + end]);
        Ok(())
    }
}
fn region(path: &std::path::Path) -> (Arc<dyn ReadAt>, Arc<AtomicBool>) {
    let payload = std::fs::read(path).unwrap();
    let mut bytes = vec![0xa5; 12345];
    let start = bytes.len();
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&[0x5a; 333]);
    let fail = Arc::new(AtomicBool::new(false));
    (
        Arc::new(Region {
            bytes,
            start,
            length: payload.len(),
            fail: fail.clone(),
        }),
        fail,
    )
}
#[test]
fn iso_writer_fixture_deferred_nonzero_region_repeats_and_retains_budget() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("nested")).unwrap();
    let payload: Vec<_> = (0..7777).map(|i| (i % 251) as u8).collect();
    std::fs::write(tree.join("nested/data.bin"), &payload).unwrap();
    let iso = dir.path().join("fixture.iso");
    libmkiso::write_iso9660(&tree, &iso).unwrap();
    let (source, fail) = region(&iso);
    let r = resources();
    let adapted = SourceAdapter::new(source, r.clone(), u64::MAX);
    let index = OpticalReadIndex::iso(
        adapted.clone(),
        13,
        5,
        libmkiso::IsoNamespace::Primary,
        limits(),
        &r,
    )
    .unwrap();
    let n = index
        .entries()
        .iter()
        .position(|e| e.display_path == "NESTED/DATA.BIN")
        .unwrap();
    assert!(!index.entries()[n].native_name.is_empty());
    let file = index.open_file(n).unwrap();
    let used = r.memory.used();
    drop(index);
    assert_eq!(r.memory.used(), used);
    let mut out = [0; 31];
    file.read_at(7700, &mut out, &r).unwrap();
    assert_eq!(&out, &payload[7700..7731]);
    file.read_at(9, &mut out, &r).unwrap();
    assert_eq!(&out, &payload[9..40]);
    let cursor_a = libmkiso::SourceCursor::new(adapted.clone());
    let cursor_b = libmkiso::SourceCursor::new(adapted.clone());
    drop((cursor_a, cursor_b));
    fail.store(true, Ordering::Release);
    let error = file.read_at(1, &mut out, &r).unwrap_err();
    assert!(error.source.is_some());
    fail.store(false, Ordering::Release);
    r.cancellation.cancel();
    assert_eq!(
        file.read_at(1, &mut out, &r).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    drop(file);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn udf_sparse_owned_stream_links_and_native_metadata_remain_deferred() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.udf");
    let mut image = libmkiso::UdfImage::new();
    image
        .add_sparse_file(
            "nested/日本語.bin",
            vec![
                libmkiso::UdfFileExtent::Data(vec![7; 2048]),
                libmkiso::UdfFileExtent::Hole(4096),
                libmkiso::UdfFileExtent::AllocatedHole(2048),
                libmkiso::UdfFileExtent::Data(vec![9; 123]),
            ],
        )
        .unwrap();
    image
        .add_hard_link("alias.bin", "nested/日本語.bin")
        .unwrap();
    image
        .add_named_stream("nested/日本語.bin", "notes", b"named".to_vec())
        .unwrap();
    image.add_symlink("link", "nested/日本語.bin").unwrap();
    image
        .write(
            &path,
            &libmkiso::UdfOptions {
                revision: libmkiso::UdfRevision::V201,
                ..Default::default()
            },
        )
        .unwrap();
    let (source, _) = region(&path);
    let r = resources();
    let index = OpticalReadIndex::udf(
        SourceAdapter::new(source, r.clone(), u64::MAX),
        33,
        6,
        limits(),
        &r,
    )
    .unwrap();
    let n = index
        .entries()
        .iter()
        .position(|e| e.display_path == "nested/日本語.bin")
        .unwrap();
    let alias = index
        .entries()
        .iter()
        .find(|e| e.display_path == "alias.bin")
        .unwrap();
    assert_eq!(alias.identity, index.entries()[n].identity);
    let file = index.open_file(n).unwrap();
    let mut out = vec![0; 300];
    file.read_at(2000, &mut out, &r).unwrap();
    assert_eq!(&out[..48], &[7; 48]);
    assert!(out[48..].iter().all(|b| *b == 0));
    let mut classes = Vec::new();
    file.visit_extents(&r, &mut |e| {
        classes.push(e.kind);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        classes,
        vec![
            partmgr::fs_core::ExtentKind::Data,
            partmgr::fs_core::ExtentKind::Hole,
            partmgr::fs_core::ExtentKind::Unwritten,
            partmgr::fs_core::ExtentKind::Data
        ]
    );
    let mut tail = [0; 123];
    file.read_at(8192, &mut tail, &r).unwrap();
    assert_eq!(tail, [9; 123]);
    let mut native = vec![16];
    for unit in "日本語.bin".encode_utf16() {
        native.extend_from_slice(&unit.to_be_bytes());
    }
    assert_eq!(index.entries()[n].native_name, native);
    let stream = index
        .entries()
        .iter()
        .position(|e| e.stream.as_ref().is_some_and(|s| s.name == "notes"))
        .unwrap();
    let mut named = [0; 5];
    index
        .open_file(stream)
        .unwrap()
        .read_at(0, &mut named, &r)
        .unwrap();
    assert_eq!(&named, b"named");
    let link = index
        .entries()
        .iter()
        .position(|e| e.display_path == "link")
        .unwrap();
    assert!(index.open_file(link).is_err());
    assert_eq!(
        index.entries()[link].link_target.as_deref(),
        Some("nested/日本語.bin")
    );
}
#[test]
fn metadata_and_source_read_budgets_fail_without_silent_empty_data() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("a"), b"data").unwrap();
    let iso = dir.path().join("fixture.iso");
    libmkiso::write_iso9660(&tree, &iso).unwrap();
    let low = Resources {
        memory: Budget::new(8),
        cancellation: Cancellation::default(),
    };
    let source = Arc::new(RawDisk::open(&iso).unwrap());
    assert_eq!(
        OpticalReadIndex::iso(
            SourceAdapter::new(source.clone(), low.clone(), u64::MAX),
            1,
            0,
            libmkiso::IsoNamespace::Primary,
            limits(),
            &low
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(low.memory.used(), 0);
    let r = resources();
    let source = SourceAdapter::new(source, r.clone(), 1);
    assert!(
        OpticalReadIndex::iso(
            source.clone(),
            1,
            0,
            libmkiso::IsoNamespace::Primary,
            limits(),
            &r
        )
        .is_err()
    );
    assert!(source.requested_bytes() <= 1);
    assert_eq!(r.memory.used(), 0);
}

struct Queries {
    context: virtdisk::ReadContext,
    budget: virtdisk::ReadBudget,
    holes_called: std::sync::atomic::AtomicU64,
}
impl ReadAt for Queries {
    fn len(&self) -> u64 {
        4096
    }
    fn context(&self) -> virtdisk::ReadContext {
        self.context.clone()
    }
    fn budget(&self) -> Option<virtdisk::ReadBudget> {
        Some(self.budget.clone())
    }
    fn sparse_holes(&self) -> io::Result<Vec<(u64, u64)>> {
        self.holes_called.fetch_add(1, Ordering::AcqRel);
        Ok(vec![(100, 200)])
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        if offset
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > 4096)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.budget.work(1)?;
        out.fill(0);
        Ok(())
    }
}
#[test]
fn source_adapter_forwards_exact_provenance_shared_budget_and_sparse_queries() {
    let context = virtdisk::ReadContext {
        container: Some("retained-container.qcow2".into()),
        partition: Some(9),
        path: Some(vec![vec![0xd800, 65]]),
        ..Default::default()
    };
    let budget = virtdisk::ReadBudget::new(virtdisk::ParserLimits::default()).unwrap();
    let source = Arc::new(Queries {
        context: context.clone(),
        budget: budget.clone(),
        holes_called: std::sync::atomic::AtomicU64::new(0),
    });
    let adapter = SourceAdapter::new(source.clone(), resources(), 8192);
    assert_eq!(ReadAt::context(&adapter), context);
    ReadAt::budget(&adapter).unwrap().work(3).unwrap();
    assert_eq!(budget.usage().work_items, 3);
    assert_eq!(ReadAt::sparse_holes(&adapter).unwrap(), vec![(100, 200)]);
    assert_eq!(source.holes_called.load(Ordering::Acquire), 1);
    ReadAt::read_exact_at(&adapter, 8, &mut [0; 4]).unwrap();
    assert_eq!(budget.usage().work_items, 4);
    assert_eq!(adapter.requested_bytes(), 4);
}

fn gate_command(
    program: &str,
    args: &[&std::ffi::OsStr],
    receipt: &mut String,
) -> std::process::Output {
    let mut command = std::process::Command::new(program);
    command.args(args);
    receipt.push_str(&format!("command={command:?}\n"));
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{command:?}: {error}"));
    receipt.push_str(&format!(
        "exit={}\nstdout={}\nstderr={}\n",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    assert!(output.status.success(), "{receipt}");
    output
}
fn available(program: &str) -> bool {
    match std::process::Command::new(program)
        .arg("--version")
        .output()
    {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => panic!("cannot inspect {program}: {error}"),
    }
}
#[test]
#[ignore = "explicit native gate requires qemu-img, sha256sum and 7z/7zz"]
fn r1_iso_udf_normal_and_compressed_qcow2_large_logical_source_gate() {
    use std::{ffi::OsStr, io::Write};
    for tool in ["qemu-img", "sha256sum"] {
        assert!(available(tool), "enabled R1 optical gate requires {tool}");
    }
    let evidence = std::env::var_os("PARTMGR_OPTICAL_READ_EVIDENCE").map(std::path::PathBuf::from);
    let dir = if let Some(destination) = &evidence {
        std::fs::create_dir_all(destination).unwrap();
        tempfile::Builder::new()
            .prefix("optical-read-r1-")
            .tempdir_in(destination)
            .unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let mut receipt = String::from(
        "profile=optical-container-r1-v1\nstatus=running\nsource_offset=8192\nlogical_disk_bytes=8589934592\nfilesystem_memory_limit=8388608\ncontainer_metadata_limit=8388608\ncontainer_cache_limit=2097152\n",
    );
    receipt.push_str(&format!(
        "libmkiso_version={}\npayload_profile=131089 bytes: (index*37+index/251+19)%256\n",
        libmkiso::VERSION
    ));
    gate_command("qemu-img", &[OsStr::new("--version")], &mut receipt);
    let seven = if available("7z") {
        Some("7z")
    } else if available("7zz") {
        Some("7zz")
    } else {
        panic!("enabled R1 optical gate requires 7z or 7zz")
    };
    if let Some(seven) = seven {
        gate_command(seven, &[OsStr::new("i")], &mut receipt);
    }
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in ["Cargo.toml", "Cargo.lock", "src/read.rs", "tests/read.rs"] {
        let path = manifest.join(relative);
        gate_command("sha256sum", &[path.as_os_str()], &mut receipt);
    }
    gate_command(
        "sha256sum",
        &[std::env::current_exe().unwrap().as_os_str()],
        &mut receipt,
    );
    receipt.push_str(&format!(
        "resolved_lockfile={}\n",
        std::fs::read_to_string(manifest.join("Cargo.lock")).unwrap()
    ));
    let payload: Vec<_> = (0..131089)
        .map(|i| ((i * 37 + i / 251 + 19) % 256) as u8)
        .collect();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("nested")).unwrap();
    std::fs::write(tree.join("nested/payload.bin"), &payload).unwrap();
    for format in ["iso", "udf"] {
        let image = dir.path().join(format!("fixture.{format}"));
        if format == "iso" {
            libmkiso::write_iso9660(&tree, &image).unwrap();
        } else {
            let mut udf = libmkiso::UdfImage::new();
            udf.add_bytes("nested/payload.bin", payload.clone())
                .unwrap();
            udf.write(&image, &libmkiso::UdfOptions::default()).unwrap();
        }
        if let Some(seven) = seven {
            let extracted = dir.path().join(format!("native-{format}"));
            let output_arg = format!("-o{}", extracted.display());
            gate_command(
                seven,
                &[
                    OsStr::new("x"),
                    OsStr::new("-y"),
                    OsStr::new(&output_arg),
                    image.as_os_str(),
                ],
                &mut receipt,
            );
            let relative = if format == "iso" {
                "NESTED/PAYLOAD.BIN"
            } else {
                "nested/payload.bin"
            };
            let extracted_payload = std::fs::read(extracted.join(relative)).unwrap();
            assert_eq!(extracted_payload, payload);
            receipt.push_str(&format!(
                "native_oracle={format} payload_bytes={} exact_match=true\n",
                payload.len()
            ));
        }
        let image_length = std::fs::metadata(&image).unwrap().len();
        let raw = dir.path().join(format!("wrapped-{format}.raw"));
        let mut output = std::fs::File::create(&raw).unwrap();
        output.write_all(&[0xa5; 8192]).unwrap();
        std::io::copy(&mut std::fs::File::open(&image).unwrap(), &mut output).unwrap();
        output.write_all(&[0x5a; 4096]).unwrap();
        output.sync_all().unwrap();
        drop(output);
        for compressed in [false, true] {
            let qcow = dir.path().join(format!(
                "{format}-{}.qcow2",
                if compressed { "compressed" } else { "normal" }
            ));
            let mut args = vec![
                OsStr::new("convert"),
                OsStr::new("-f"),
                OsStr::new("raw"),
                OsStr::new("-O"),
                OsStr::new("qcow2"),
            ];
            if compressed {
                args.push(OsStr::new("-c"));
            }
            args.extend([raw.as_os_str(), qcow.as_os_str()]);
            gate_command("qemu-img", &args, &mut receipt);
            gate_command(
                "qemu-img",
                &[OsStr::new("resize"), qcow.as_os_str(), OsStr::new("8G")],
                &mut receipt,
            );
            gate_command(
                "qemu-img",
                &[OsStr::new("check"), qcow.as_os_str()],
                &mut receipt,
            );
            gate_command(
                "qemu-img",
                &[
                    OsStr::new("info"),
                    OsStr::new("--output=json"),
                    qcow.as_os_str(),
                ],
                &mut receipt,
            );
            let parser_limits = virtdisk::ParserLimits {
                metadata_bytes: 8 * 1024 * 1024,
                cache_bytes: 2 * 1024 * 1024,
                work_items: 1_000_000,
                decompressed_bytes: 64 * 1024 * 1024,
                decompression_buffer_bytes: 64 * 1024,
                ..Default::default()
            };
            let disk = Arc::new(
                virtdisk::Qcow2::open_with_limits(
                    Arc::new(RawDisk::open(&qcow).unwrap()),
                    parser_limits,
                )
                .unwrap(),
            );
            assert_eq!(disk.len(), 8 * 1024 * 1024 * 1024);
            let view = Arc::new(
                virtdisk::DiskView::new(disk, 8192, image_length)
                    .unwrap()
                    .with_partition(9),
            );
            let r = resources();
            let adapter = SourceAdapter::new(view, r.clone(), 16 * 1024 * 1024);
            assert_eq!(ReadAt::context(&adapter).partition, Some(9));
            assert_eq!(
                ReadAt::context(&adapter).container,
                Some(qcow.canonicalize().unwrap())
            );
            let container_budget = ReadAt::budget(&adapter).unwrap();
            assert_eq!(container_budget.limits(), parser_limits);
            let index = if format == "iso" {
                OpticalReadIndex::iso(
                    adapter.clone(),
                    77,
                    1,
                    libmkiso::IsoNamespace::Primary,
                    limits(),
                    &r,
                )
            } else {
                OpticalReadIndex::udf(adapter.clone(), 77, 1, limits(), &r)
            }
            .unwrap();
            let path = if format == "iso" {
                "NESTED/PAYLOAD.BIN"
            } else {
                "nested/payload.bin"
            };
            let entry = index
                .entries()
                .iter()
                .position(|e| e.display_path == path)
                .unwrap();
            let file = index.open_file(entry).unwrap();
            drop(index);
            let mut seed = 0x1234_u64;
            let mut offsets = vec![0, 7, 65530, payload.len() as u64 - 37, payload.len() as u64];
            for _ in 0..64 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                offsets.push(seed % payload.len() as u64);
            }
            let mut out = [0; 4096];
            for offset in offsets {
                let count = file.read_at(offset, &mut out, &r).unwrap();
                let expected = (payload.len() - offset as usize).min(out.len());
                assert_eq!(count, expected);
                assert_eq!(
                    &out[..count],
                    &payload[offset as usize..offset as usize + count]
                );
            }
            assert!(r.memory.used() < 8 * 1024 * 1024);
            let usage = container_budget.usage();
            assert!(usage.cache_bytes <= 2 * 1024 * 1024);
            assert!(usage.metadata_bytes <= 8 * 1024 * 1024);
            if compressed {
                assert!(
                    usage.decompressed_bytes > 0,
                    "compressed fixture must exercise actual decoder"
                );
            } else {
                assert_eq!(usage.decompressed_bytes, 0);
            }
            receipt.push_str(&format!("case={format} compressed={compressed} expected_bytes={} random_ranges=69 exact_match=true retained_filesystem_bytes={} container_usage={usage:?} requested_bytes={}\n",payload.len(),r.memory.used(),adapter.requested_bytes()));
            drop(file);
            drop(adapter);
            assert_eq!(r.memory.used(), 0);
            assert_eq!(container_budget.usage().cache_bytes, 0);
        }
    }
    receipt.push_str("status=passed\n");
    if let Some(destination) = evidence {
        std::fs::create_dir_all(&destination).unwrap();
        let retained = dir.keep();
        std::fs::write(
            destination.join("optical-container-r1-v1.txt"),
            format!("artifact_directory={}\n{receipt}", retained.display()),
        )
        .unwrap();
    }
    eprintln!(
        "PASSED optical-container-r1-v1: ISO/UDF normal/compressed QCOW2, 8 GiB logical, offset 8192, 69 payload ranges per case; native oracle available={}",
        seven.is_some()
    );
}
