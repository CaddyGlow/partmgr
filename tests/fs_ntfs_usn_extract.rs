use partmgr::{fs_core::*, fs_ntfs::*, fs_ntfs_usn::RecordLimits, fs_ntfs_usn_extract::*};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;
#[path = "fixtures/ntfs_clean.rs"]
mod fixture;
struct Image {
    bytes: Vec<u8>,
    fail: AtomicU64,
    reads: AtomicU64,
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if offset >= self.fail.load(Ordering::Relaxed) {
            return Err(io::Error::other("injected journal read"));
        }
        let at = usize::try_from(offset).map_err(io::Error::other)?;
        output.copy_from_slice(
            self.bytes
                .get(at..at + output.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
fn streams() -> NtfsStreamLimits {
    NtfsStreamLimits {
        extension_records: 8,
        list_entries: 32,
        list_bytes: 8192,
        attributes: 128,
        runs: 128,
        work: 65536,
    }
}
fn journal() -> JournalLimits {
    JournalLimits {
        record: RecordLimits {
            record_bytes: 1024,
            name_units: 128,
        },
        records: 8,
        extents: 16,
        read_bytes: 8192,
        work: 4096,
    }
}
fn record_bytes() -> Vec<u8> {
    let fixture = include_bytes!("fixtures/ntfs_usn_mixed.bin");
    fixture[..u32::from_le_bytes(fixture[..4].try_into().unwrap()) as usize].to_vec()
}
fn named_resident(payload: &[u8]) -> Vec<u8> {
    let mut a = fixture::resident(0x80, &[vec![0; 8], payload.to_vec()].concat(), 3);
    a[9] = 2;
    fixture::w(&mut a, 10, 24);
    fixture::w(&mut a, 20, 32);
    fixture::d(&mut a, 16, payload.len() as u32);
    a[24..28].copy_from_slice(&[36, 0, 74, 0]);
    a
}
fn named_sparse() -> Vec<u8> {
    let old = fixture::nonresident(&[0x11, 1, 90, 0x01, 1, 0x11, 1, 1, 0], 3, 1536, 1280, true);
    let mut a = old[..72].to_vec();
    a.extend_from_slice(&[36, 0, 74, 0, 0, 0, 0, 0]);
    a.extend_from_slice(&old[72..]);
    let len = a.len();
    fixture::d(&mut a, 4, len as u32);
    a[9] = 2;
    fixture::w(&mut a, 10, 72);
    fixture::w(&mut a, 32, 80);
    a
}
fn image(attribute: Vec<u8>) -> Vec<u8> {
    let mut b = vec![0; 128 * 512];
    b[3..11].copy_from_slice(b"NTFS    ");
    fixture::w(&mut b, 11, 512);
    b[13] = 1;
    fixture::q(&mut b, 40, 128);
    fixture::q(&mut b, 48, 4);
    fixture::q(&mut b, 56, 100);
    b[64] = (-10i8) as u8;
    b[68] = (-10i8) as u8;
    fixture::w(&mut b, 510, 0xaa55);
    let mut volume = vec![0; 12];
    volume[8] = 3;
    volume[9] = 1;
    for (n, attrs) in [
        (
            0,
            vec![fixture::nonresident(
                &[0x11, 64, 4, 0],
                64,
                32768,
                32768,
                false,
            )],
        ),
        (3, vec![fixture::resident(0x70, &volume, 1)]),
        (24, vec![fixture::resident(0x10, &[0; 72], 1), attribute]),
    ] {
        b[2048 + n * 1024..2048 + (n + 1) * 1024]
            .copy_from_slice(&fixture::record(n as u32, &attrs));
    }
    b
}
fn open(b: Vec<u8>, j: JournalLimits, r: &Resources) -> (Arc<Image>, NtfsVolume, NtfsUsnReader) {
    let source = Arc::new(Image {
        bytes: b,
        fail: AtomicU64::new(u64::MAX),
        reads: AtomicU64::new(0),
    });
    let volume = NtfsVolume::open(
        source.clone(),
        NtfsReadLimits {
            attributes: 128,
            runs: 128,
            names: 32,
        },
        r,
    )
    .unwrap();
    let owner = volume.stream_identity(24, r).unwrap();
    let reader = NtfsUsnReader::open(&volume, &owner, streams(), j, [0x6a; 32], r).unwrap();
    (source, volume, reader)
}
#[test]
fn exact_resident_records_padding_owner_and_refunds() {
    let r = resources();
    let record = record_bytes();
    let mut payload = record.clone();
    payload.extend([0; 8]);
    payload.extend_from_slice(&record);
    let (_, volume, reader) = open(image(named_resident(&payload)), journal(), &r);
    let baseline = r.memory.used();
    let mut offsets = vec![];
    let mut gaps = vec![];
    reader
        .visit(&r, &mut |event| {
            match event {
                JournalEvent::Record {
                    owner,
                    record: actual,
                } => {
                    assert_eq!(owner, reader.owner());
                    assert_eq!(actual.raw(), record);
                    assert_eq!(actual.provenance.evidence_id, [0x6a; 32]);
                    offsets.push(actual.provenance.offset);
                }
                JournalEvent::Gap {
                    offset,
                    length,
                    kind,
                    ..
                } => gaps.push((offset, length, kind)),
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(offsets, [0, record.len() as u64 + 8]);
    assert_eq!(gaps, [(record.len() as u64, 8, GapKind::ZeroPadding)]);
    assert_eq!(r.memory.used(), baseline);
    drop(volume);
    reader.visit(&r, &mut |_| Ok(())).unwrap();
    drop(reader);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn sparse_and_unwritten_ranges_are_explicit_and_record_cannot_cross_gap() {
    let record = record_bytes();
    let mut b = image(named_sparse());
    b[90 * 512..90 * 512 + record.len()].copy_from_slice(&record);
    b[91 * 512..91 * 512 + record.len()].copy_from_slice(&record);
    let r = resources();
    let (_, volume, reader) = open(b.clone(), journal(), &r);
    let baseline = r.memory.used();
    let mut records = vec![];
    let mut gaps = vec![];
    reader
        .visit(&r, &mut |e| {
            match e {
                JournalEvent::Record { record, .. } => records.push(record.provenance.offset),
                JournalEvent::Gap {
                    offset,
                    length,
                    kind,
                    ..
                } if kind != GapKind::ZeroPadding => gaps.push((offset, length, kind)),
                _ => {}
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(records, [0, 1024]);
    assert_eq!(
        gaps,
        [(512, 512, GapKind::Sparse), (1280, 256, GapKind::Unwritten)]
    );
    assert_eq!(r.memory.used(), baseline);
    drop((reader, volume));
    assert_eq!(r.memory.used(), 0);
    fixture::d(&mut b, 90 * 512, 600);
    let (_, volume, reader) = open(b, journal(), &r);
    assert!(matches!(
        reader.visit(&r, &mut |_| Ok(())),
        Err(ExtractError::Core(Error {
            kind: ErrorKind::InvalidData,
            ..
        }))
    ));
    drop((reader, volume));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn bounded_reads_work_records_cancellation_decode_and_causal_io() {
    let record = record_bytes();
    for limit in [
        JournalLimits {
            work: 0,
            ..journal()
        },
        JournalLimits {
            records: 0,
            ..journal()
        },
        JournalLimits {
            read_bytes: 7,
            ..journal()
        },
        JournalLimits {
            extents: 0,
            ..journal()
        },
    ] {
        let r = resources();
        let (_, volume, reader) = open(image(named_resident(&record)), limit, &r);
        let baseline = r.memory.used();
        assert!(reader.visit(&r, &mut |_| Ok(())).is_err());
        assert_eq!(r.memory.used(), baseline);
        drop((reader, volume));
        assert_eq!(r.memory.used(), 0);
    }
    let r = resources();
    let mut b = image(named_sparse());
    b[90 * 512..90 * 512 + record.len()].copy_from_slice(&record);
    let (source, volume, reader) = open(b, journal(), &r);
    source.fail.store(90 * 512, Ordering::Relaxed);
    let error = reader.visit(&r, &mut |_| Ok(())).unwrap_err();
    assert!(matches!(
        error,
        ExtractError::Core(Error {
            kind: ErrorKind::Io,
            ..
        })
    ));
    drop((reader, volume));
    assert_eq!(r.memory.used(), 0);
    let r = resources();
    let (source, volume, reader) = open(image(named_resident(&record)), journal(), &r);
    let reads = source.reads.load(Ordering::Relaxed);
    r.cancellation.cancel();
    assert!(reader.visit(&r, &mut |_| Ok(())).is_err());
    assert_eq!(source.reads.load(Ordering::Relaxed), reads);
    drop((reader, volume));
    assert_eq!(r.memory.used(), 0);
    let r = resources();
    let mut bad = record;
    fixture::w(&mut bad, 4, 99);
    let (_, volume, reader) = open(image(named_resident(&bad)), journal(), &r);
    match reader.visit(&r, &mut |_| Ok(())).unwrap_err() {
        ExtractError::Decode(error) => {
            assert_eq!(error.provenance.offset, 0);
            assert_eq!(
                error.kind,
                partmgr::fs_ntfs_usn::ErrorKind::UnsupportedVersion
            );
        }
        other => panic!("{other:?}"),
    };
    drop((reader, volume));
    assert_eq!(r.memory.used(), 0);
}

#[test]
#[ignore = "requires explicit disposable native image, inode, oracle and fresh evidence directory"]
fn native_named_stream_exact_extraction_and_independent_oracle() {
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf, process::Command};
    let image =
        PathBuf::from(std::env::var_os("PARTMGR_USN_NATIVE_IMAGE").expect("native image required"));
    let inode: u64 = std::env::var("PARTMGR_USN_NATIVE_INODE")
        .expect("native inode required")
        .parse()
        .unwrap();
    let expected = PathBuf::from(
        std::env::var_os("PARTMGR_USN_NATIVE_ORACLE").expect("independent oracle required"),
    );
    let out = PathBuf::from(
        std::env::var_os("PARTMGR_USN_NATIVE_EVIDENCE").expect("fresh native evidence required"),
    );
    fs::create_dir(&out).unwrap();
    let sources: [(&str, &[u8]); 10] = [
        (
            "src/fs_ntfs_usn_extract.rs",
            include_bytes!("../src/fs_ntfs_usn_extract.rs"),
        ),
        (
            "src/fs_ntfs_usn.rs",
            include_bytes!("../src/fs_ntfs_usn.rs"),
        ),
        ("src/fs_ntfs.rs", include_bytes!("../src/fs_ntfs.rs")),
        (
            "src/fs_ntfs_stream.rs",
            include_bytes!("../src/fs_ntfs_stream.rs"),
        ),
        (
            "src/fs_ntfs_bootstrap.rs",
            include_bytes!("../src/fs_ntfs_bootstrap.rs"),
        ),
        ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
        ("src/fs_file.rs", include_bytes!("../src/fs_file.rs")),
        ("Cargo.lock", include_bytes!("../Cargo.lock")),
        ("src/lib.rs", include_bytes!("../src/lib.rs")),
        (
            "tests/fs_ntfs_usn_extract.rs",
            include_bytes!("fs_ntfs_usn_extract.rs"),
        ),
    ];
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut manifest = String::new();
    for (name, bytes) in sources {
        assert_eq!(
            Sha256::digest(bytes),
            Sha256::digest(fs::read(root.join(name)).unwrap())
        );
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
        manifest.push_str(&format!("{name} {:x}\n", Sha256::digest(bytes)));
    }
    fs::write(out.join("source-start.sha256"), &manifest).unwrap();
    let executable = fs::read(std::env::current_exe().unwrap()).unwrap();
    fs::write(out.join("compiled-test"), &executable).unwrap();
    let tool = "/nix/store/3ankmn51mpka2xrhnyma5kfn16y59br8-ntfs3g-2026.9.18/bin/ntfscat";
    let toolhash = Sha256::digest(fs::read(tool).unwrap());
    fs::write(out.join("tool.sha256"), format!("{tool} {toolhash:x}\n")).unwrap();
    let command = Command::new(tool)
        .args([
            "-i",
            &inode.to_string(),
            "-n",
            "$J",
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    fs::write(
        out.join("oracle-command.txt"),
        format!("{tool} -i {inode} -n $J {}\n", image.display()),
    )
    .unwrap();
    fs::write(out.join("oracle.stderr"), &command.stderr).unwrap();
    assert!(command.status.success());
    fs::write(out.join("native-J.bin"), &command.stdout).unwrap();
    assert_eq!(command.stdout, fs::read(&expected).unwrap());
    let original = fs::read(&image).unwrap();
    let hash = Sha256::digest(&original);
    let r = resources();
    let volume = NtfsVolume::open_stream_profile(
        Arc::new(Image {
            bytes: original,
            fail: AtomicU64::new(u64::MAX),
            reads: AtomicU64::new(0),
        }),
        NtfsReadLimits {
            attributes: 128,
            runs: 128,
            names: 32,
        },
        streams(),
        &r,
    )
    .unwrap();
    let owner = volume.stream_identity(inode, &r).unwrap();
    let limits = JournalLimits {
        records: 2048,
        extents: 256,
        read_bytes: 1 << 20,
        work: 1 << 20,
        ..journal()
    };
    let reader = NtfsUsnReader::open(&volume, &owner, streams(), limits, [0x6a; 32], &r).unwrap();
    let baseline = r.memory.used();
    let mut bytes = Vec::new();
    let mut records = 0;
    reader
        .visit(&r, &mut |event| {
            match event {
                JournalEvent::Record {
                    owner: actual,
                    record,
                } => {
                    assert_eq!(actual, &owner);
                    assert_eq!(record.provenance.offset, bytes.len() as u64);
                    bytes.extend_from_slice(record.raw());
                    records += 1;
                }
                JournalEvent::Gap { .. } => {
                    panic!("dense synthetic journal fixture must contain only records")
                }
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(bytes, command.stdout);
    assert_eq!(records, 1024);
    assert_eq!(r.memory.used(), baseline);
    drop((reader, volume));
    assert_eq!(r.memory.used(), 0);
    fs::write(out.join("extracted-J.bin"), bytes).unwrap();
    fs::write(out.join("record-count.txt"), records.to_string()).unwrap();
    assert_eq!(hash, Sha256::digest(fs::read(&image).unwrap()));
    fs::write(out.join("image.sha256"), format!("{hash:x}\n")).unwrap();
    assert_eq!(toolhash, Sha256::digest(fs::read(tool).unwrap()));
    for (name, bytes) in sources {
        assert_eq!(
            Sha256::digest(bytes),
            Sha256::digest(fs::read(root.join(name)).unwrap())
        );
    }
    fs::write(out.join("source-end.sha256"), manifest).unwrap();
}
