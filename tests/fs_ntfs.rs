#![cfg(feature = "std")]

use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, ExtentKind, FileRead, NativeName, Resources},
    fs_ntfs::{NtfsReadLimits, NtfsVolume},
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;
struct Image {
    bytes: Vec<u8>,
    reads: AtomicU64,
    length: AtomicU64,
    fail: AtomicU64,
}
impl Image {
    fn new(bytes: Vec<u8>) -> Self {
        let n = bytes.len() as u64;
        Self {
            bytes,
            reads: AtomicU64::new(0),
            length: AtomicU64::new(n),
            fail: AtomicU64::new(u64::MAX),
        }
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.length.load(Ordering::Relaxed)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if o >= self.fail.load(Ordering::Relaxed) {
            return Err(io::Error::other("injected read failure"));
        }
        let p = usize::try_from(o).map_err(io::Error::other)?;
        b.copy_from_slice(
            self.bytes
                .get(p..p + b.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn r() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> NtfsReadLimits {
    NtfsReadLimits {
        attributes: 32,
        runs: 64,
        names: 8,
    }
}
#[path = "fixtures/ntfs_basic.rs"]
mod basic_fixture;
use basic_fixture::*;
#[test]
fn resident_native_names_identity_and_refunds() {
    let r = r();
    let source = Arc::new(Image::new(fixture()));
    {
        let v = NtfsVolume::open(source.clone(), limits(), &r).unwrap();
        assert_eq!(v.record_count(), 32);
        let rec = v.record(24, &r).unwrap();
        assert_eq!(rec.names()[0].name, NativeName::Utf16(vec![0x65e5, 0xd800]));
        let f = v.open_object(rec.identity(), &r).unwrap();
        let before = source.reads.load(Ordering::Relaxed);
        let mut b = [0; 8];
        assert_eq!(f.read_at(0, &mut b, &r).unwrap(), 5);
        assert_eq!(&b[..5], b"hello");
        assert_eq!(f.read_at(5, &mut b, &r).unwrap(), 0);
        assert_eq!(source.reads.load(Ordering::Relaxed), before);
        let mut stale = rec.identity().clone();
        stale.generation += 1;
        assert_eq!(
            v.open_object(&stale, &r).err().unwrap().kind,
            ErrorKind::StalePlan
        );
    }
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn sparse_and_uninitialized_are_distinct_deferred_zeros() {
    let r = r();
    let source = Arc::new(Image::new(fixture()));
    let v = NtfsVolume::open(source.clone(), limits(), &r).unwrap();
    source.fail.store(90 * 512, Ordering::Relaxed);
    let f = v.open_file(25, &r).unwrap();
    source.fail.store(u64::MAX, Ordering::Relaxed);
    let mut ext = vec![];
    f.visit_extents(&r, &mut |e| {
        ext.push(e);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        ext.iter().map(|e| e.kind.clone()).collect::<Vec<_>>(),
        vec![
            ExtentKind::Data,
            ExtentKind::Hole,
            ExtentKind::Data,
            ExtentKind::Unwritten
        ]
    );
    let n = source.reads.load(Ordering::Relaxed);
    let mut zero = [0xff; 256];
    f.read_at(512, &mut zero, &r).unwrap();
    assert_eq!(zero, [0; 256]);
    f.read_at(1280, &mut zero, &r).unwrap();
    assert_eq!(source.reads.load(Ordering::Relaxed), n);
    let mut b = vec![0; 1600];
    assert_eq!(f.read_at(0, &mut b, &r).unwrap(), 1536);
    assert!(b[..512].iter().all(|v| *v == 0x31));
    assert!(b[512..1024].iter().all(|v| *v == 0));
    assert!(b[1024..1280].iter().all(|v| *v == 0x72));
    assert!(b[1280..1536].iter().all(|v| *v == 0));
    source.fail.store(90 * 512, Ordering::Relaxed);
    assert_eq!(
        f.read_at(0, &mut b[..1], &r).unwrap_err().kind,
        ErrorKind::Io
    );
    source.length.store(1, Ordering::Relaxed);
    assert_eq!(
        f.read_at(9999, &mut b, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
}
#[test]
fn malformed_headers_fixups_and_dirty_are_rejected() {
    for (offset, value, kind) in [
        (510, 0, ErrorKind::InvalidData),
        (2048 + 510, 0, ErrorKind::InvalidData),
        (2048 + 29, 0, ErrorKind::InvalidData),
        (2048 + 3 * 1024 + 56 + 24 + 10, 1, ErrorKind::Unsupported),
    ] {
        let mut b = fixture();
        b[offset] = value;
        let r = r();
        assert_eq!(
            NtfsVolume::open(Arc::new(Image::new(b)), limits(), &r)
                .err()
                .unwrap()
                .kind,
            kind
        );
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn malformed_runs_and_unsupported_attribute_list() {
    for attrs in [
        vec![nonresident(&[0x19, 1, 90, 0], 1, 512, 512, false)],
        vec![nonresident(&[0x11, 0, 90, 0], 1, 512, 512, false)],
        vec![nonresident(
            &[0x11, 1, 127, 0x11, 1, 1, 0],
            2,
            1024,
            1024,
            false,
        )],
        vec![resident(0x20, &[], 1)],
    ] {
        let mut b = fixture();
        let p = 2048 + 25 * 1024;
        b[p..p + 1024].copy_from_slice(&record(25, &attrs));
        let r = r();
        let v = NtfsVolume::open(Arc::new(Image::new(b)), limits(), &r).unwrap();
        assert!(v.open_file(25, &r).is_err());
    }
}
#[test]
fn cancellation_budget_and_bounds_prevent_reads() {
    let source = Arc::new(Image::new(fixture()));
    let r = r();
    r.cancellation.cancel();
    assert_eq!(
        NtfsVolume::open(source.clone(), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);
    let r = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        NtfsVolume::open(source.clone(), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
    let r = self::r();
    let v = NtfsVolume::open(source.clone(), limits(), &r).unwrap();
    let reads = source.reads.load(Ordering::Relaxed);
    assert!(v.record(32, &r).is_err());
    assert_eq!(source.reads.load(Ordering::Relaxed), reads);
    r.cancellation.cancel();
    assert_eq!(
        v.open_file(24, &r).err().unwrap().kind,
        ErrorKind::Cancelled
    );
}
#[test]
#[ignore = "explicit native NTFS gate; requires mkntfs, ntfscp, fls, icat and PARTMGR_NTFS_EVIDENCE"]
fn native_mkntfs_tsk_oracle() {
    use sha2::{Digest, Sha256};
    use std::{fs, process::Command};
    let out = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_NTFS_EVIDENCE").expect("evidence directory required"),
    );
    fs::create_dir(&out).expect("fresh evidence directory required");
    let mut receipt = format!(
        "reader_source_sha256={:x}\nfixture_source_sha256={:x}\ntest_binary_sha256={:x}\n",
        Sha256::digest(include_bytes!("../src/fs_ntfs.rs")),
        Sha256::digest(include_bytes!("fs_ntfs.rs")),
        Sha256::digest(fs::read(std::env::current_exe().unwrap()).unwrap())
    );
    for tool in ["mkntfs", "ntfscp", "fls", "icat"] {
        let path = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
            .expect("required tool binary");
        receipt.push_str(&format!(
            "tool={tool} path={} sha256={:x}\n",
            path.display(),
            Sha256::digest(fs::read(&path).unwrap())
        ));
    }
    let run = |receipt: &mut String, tool: &str, args: Vec<String>| {
        let result = Command::new(tool)
            .args(&args)
            .output()
            .unwrap_or_else(|e| panic!("required {tool}: {e}"));
        let ordinal = receipt.matches("command=").count();
        let stdout_file = format!("command-{ordinal:02}-{tool}.stdout");
        let stderr_file = format!("command-{ordinal:02}-{tool}.stderr");
        fs::write(out.join(&stdout_file), &result.stdout).unwrap();
        fs::write(out.join(&stderr_file), &result.stderr).unwrap();
        receipt.push_str(&format!("command={tool} {args:?}\nstatus={}\nstdout={stdout_file} sha256={:x}\nstderr={stderr_file} sha256={:x}\n",result.status,Sha256::digest(&result.stdout),Sha256::digest(&result.stderr)));
        fs::write(out.join("receipt.txt"), &*receipt).unwrap();
        assert!(
            result.status.success(),
            "{tool}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        result.stdout
    };
    let image = out.join("native.ntfs");
    fs::File::create(&image).unwrap().set_len(64 << 20).unwrap();
    run(&mut receipt, "mkntfs", vec!["--version".into()]);
    run(&mut receipt, "fls", vec!["-V".into()]);
    run(&mut receipt, "icat", vec!["-V".into()]);
    run(&mut receipt, "ntfscp", vec!["--version".into()]);
    run(&mut receipt, "uname", vec!["-a".into()]);
    run(
        &mut receipt,
        "mkntfs",
        vec![
            "-F".into(),
            "-Q".into(),
            "-s".into(),
            "512".into(),
            "-c".into(),
            "4096".into(),
            image.display().to_string(),
        ],
    );
    for (name, n) in [("tiny.txt", 13), ("payload.bin", 131089)] {
        let bytes = (0..n)
            .map(|i| ((i * 37 + 11) % 251) as u8)
            .collect::<Vec<_>>();
        let host = out.join(name);
        fs::write(&host, &bytes).unwrap();
        run(
            &mut receipt,
            "ntfscp",
            vec![
                image.display().to_string(),
                host.display().to_string(),
                format!("/{name}"),
            ],
        );
    }
    let before = fs::read(&image).unwrap();
    let digest = format!("{:x}", Sha256::digest(&before));
    let listing = String::from_utf8(run(
        &mut receipt,
        "fls",
        vec!["-f".into(), "ntfs".into(), image.display().to_string()],
    ))
    .unwrap();
    let r = r();
    let v = NtfsVolume::open(Arc::new(Image::new(before)), limits(), &r).unwrap();
    for name in ["tiny.txt", "payload.bin"] {
        let line = listing
            .lines()
            .find(|s| s.ends_with(&format!(":\t{name}")))
            .unwrap_or_else(|| panic!("missing name {name} in {listing}"));
        let reference = line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .trim_end_matches(':');
        let number = reference.split('-').next().unwrap().parse::<u64>().unwrap();
        let oracle = run(
            &mut receipt,
            "icat",
            vec![
                "-f".into(),
                "ntfs".into(),
                image.display().to_string(),
                reference.into(),
            ],
        );
        let expected = fs::read(out.join(name)).unwrap();
        assert_eq!(oracle, expected);
        let rec = v.record(number, &r).unwrap();
        assert!(
            rec.names()
                .iter()
                .any(|n| n.name == NativeName::Utf16(name.encode_utf16().collect()))
        );
        let f = v.open_file(number, &r).unwrap();
        let mut got = vec![0; f.len() as usize + 7];
        assert_eq!(f.read_at(0, &mut got, &r).unwrap(), expected.len());
        assert_eq!(&got[..expected.len()], expected);
        for offset in [0, 3, expected.len() - 1] {
            let mut b = [0; 19];
            let n = f.read_at(offset as u64, &mut b, &r).unwrap();
            assert_eq!(&b[..n], &expected[offset..offset + n]);
        }
        fs::write(out.join(format!("{name}.oracle")), &oracle).unwrap();
        receipt.push_str(&format!(
            "file={name} record={number} bytes={} sha256={:x}\n",
            expected.len(),
            Sha256::digest(&expected)
        ));
    }
    assert_eq!(
        digest,
        format!("{:x}", Sha256::digest(fs::read(&image).unwrap()))
    );
    receipt.push_str(&format!("source_sha256={digest}\nstatus=passed\n"));
    fs::write(out.join("receipt.txt"), receipt).unwrap();
}
#[test]
fn negative_lcn_delta_and_attribute_bounds() {
    let mut bytes = fixture();
    let p = 2048 + 25 * 1024;
    bytes[p..p + 1024].copy_from_slice(&record(
        25,
        &[nonresident(
            &[0x11, 1, 91, 0x11, 1, 0xff, 0],
            2,
            1024,
            1024,
            false,
        )],
    ));
    let r = r();
    let v = NtfsVolume::open(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
    let f = v.open_file(25, &r).unwrap();
    let mut got = [0; 1024];
    f.read_at(0, &mut got, &r).unwrap();
    assert!(got[..512].iter().all(|b| *b == 0x72));
    assert!(got[512..].iter().all(|b| *b == 0x31));
    for offset in [p + 56 + 4, p + 56 + 32] {
        let mut bytes = fixture();
        bytes[offset] = 0xff;
        let v = NtfsVolume::open(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
        assert_eq!(
            v.open_file(25, &r).err().unwrap().kind,
            ErrorKind::InvalidData
        );
    }
}
#[test]
fn work_limits_and_open_failures_refund() {
    let r = r();
    let source = Arc::new(Image::new(fixture()));
    source.fail.store(2048, Ordering::Relaxed);
    assert_eq!(
        NtfsVolume::open(source.clone(), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Io
    );
    assert_eq!(r.memory.used(), 0);
    source.fail.store(u64::MAX, Ordering::Relaxed);
    let mut limit = limits();
    limit.runs = 1;
    let v = NtfsVolume::open(source, limit, &r).unwrap();
    let baseline = r.memory.used();
    assert_eq!(
        v.open_file(25, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), baseline);
    let f = v.open_file(24, &r).unwrap();
    fn shared<T: Send + Sync>(_: &T) {}
    shared(&v);
    shared(&f);
    r.cancellation.cancel();
    assert_eq!(
        f.read_at(0, &mut [0], &r).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    drop(f);
    drop(v);
    assert_eq!(r.memory.used(), 0);
}
fn stream_limits() -> partmgr::fs_ntfs::NtfsStreamLimits {
    partmgr::fs_ntfs::NtfsStreamLimits {
        extension_records: 8,
        list_entries: 64,
        list_bytes: 65536,
        attributes: 128,
        runs: 256,
        work: 100000,
    }
}
fn named_resident(name: &[u16], value: &[u8], id: u16) -> Vec<u8> {
    let value_at = (24 + name.len() * 2).next_multiple_of(8);
    let mut a = vec![0; (value_at + value.len()).next_multiple_of(8)];
    let len = a.len();
    d(&mut a, 0, 0x80);
    d(&mut a, 4, len as u32);
    a[9] = name.len() as u8;
    w(&mut a, 10, 24);
    w(&mut a, 14, id);
    d(&mut a, 16, value.len() as u32);
    w(&mut a, 20, value_at as u16);
    for (i, u) in name.iter().enumerate() {
        w(&mut a, 24 + i * 2, *u);
    }
    a[value_at..value_at + value.len()].copy_from_slice(value);
    a
}
fn list_entry(kind: u32, name: &[u16], low: u64, number: u64, sequence: u16, id: u16) -> Vec<u8> {
    let mut b = vec![0; (26 + name.len() * 2).next_multiple_of(8)];
    let len = b.len();
    d(&mut b, 0, kind);
    w(&mut b, 4, len as u16);
    b[6] = name.len() as u8;
    b[7] = 26;
    q(&mut b, 8, low);
    q(&mut b, 16, number | (u64::from(sequence) << 48));
    w(&mut b, 24, id);
    for (i, u) in name.iter().enumerate() {
        w(&mut b, 26 + i * 2, *u);
    }
    b
}
fn ads_fixture(extension: bool, segmented: bool) -> Vec<u8> {
    let mut bytes = fixture();
    bytes.resize(1024 * 512, 0);
    q(&mut bytes, 40, 1024);
    let name = [0x61, 0xd800, 0x0000, 0xffff];
    let ads = if segmented {
        let mut a = nonresident(&[0x21, 160, 200, 0, 0], 160, 131089, 130001, false);
        // Native named nonresident prefix, mapping starts after its exact name.
        let mut output = vec![0; 88];
        output[..64].copy_from_slice(&a[..64]);
        output[9] = name.len() as u8;
        w(&mut output, 10, 64);
        w(&mut output, 14, 9);
        w(&mut output, 32, 80);
        d(&mut output, 4, 88);
        q(&mut output, 40, 257 * 512);
        for (i, u) in name.iter().enumerate() {
            w(&mut output, 64 + i * 2, *u);
        }
        output[80..85].copy_from_slice(&[0x21, 160, 200, 0, 0]);
        a.clear();
        output
    } else {
        named_resident(&name, b"secret-ads", 9)
    };
    let mut attrs = vec![resident(0x10, &[0; 72], 1)];
    if extension {
        let mut list = list_entry(0x10, &[], 0, 24, 7, 1);
        list.extend(list_entry(0x80, &[], 0, 24, 7, 3));
        list.extend(list_entry(0x80, &name, 0, 26, 7, 9));
        if segmented {
            list.extend(list_entry(0x80, &name, 160, 27, 7, 10));
        }
        attrs.push(resident(0x20, &list, 4));
        attrs.push(resident(0x80, b"base", 3));
        let mut ext = record(26, &[ads]);
        q(&mut ext, 32, 24 | (7 << 48));
        bytes[2048 + 26 * 1024..2048 + 27 * 1024].copy_from_slice(&ext);
        if segmented {
            let mut continuation = vec![0; 88];
            d(&mut continuation, 0, 0x80);
            d(&mut continuation, 4, 88);
            continuation[8] = 1;
            continuation[9] = name.len() as u8;
            w(&mut continuation, 10, 64);
            w(&mut continuation, 14, 10);
            q(&mut continuation, 16, 160);
            q(&mut continuation, 24, 256);
            w(&mut continuation, 32, 80);
            for (i, u) in name.iter().enumerate() {
                w(&mut continuation, 64 + i * 2, *u);
            }
            continuation[80..85].copy_from_slice(&[0x21, 97, 144, 1, 0]);
            let mut ext = record(27, &[continuation]);
            q(&mut ext, 32, 24 | (7 << 48));
            bytes[2048 + 27 * 1024..2048 + 28 * 1024].copy_from_slice(&ext);
            for i in 0..131089usize {
                let physical = if i < 160 * 512 {
                    200 * 512 + i
                } else {
                    400 * 512 + i - 160 * 512
                };
                bytes[physical] = (i.wrapping_mul(31) + i / 53) as u8;
            }
        }
    } else {
        attrs.extend([resident(0x80, b"base", 3), ads]);
    }
    let base = record(24, &attrs);
    bytes[2048 + 24 * 1024..2048 + 25 * 1024].copy_from_slice(&base);
    bytes
}
#[test]
fn named_resident_ads_exact_names_owner_identity_and_refunds() {
    let r = r();
    let source = Arc::new(Image::new(ads_fixture(false, false)));
    {
        let v = NtfsVolume::open(source.clone(), limits(), &r).unwrap();
        let record = v.record(24, &r).unwrap();
        let id = record.identity();
        // Existing strict capture semantics remain unchanged, explicit stream profile required.
        assert_eq!(
            v.open_object(id, &r).err().unwrap().kind,
            ErrorKind::Unsupported
        );
        let streams = v.data_streams(id, stream_limits(), &r).unwrap();
        assert_eq!(streams.get().len(), 2);
        assert_eq!(streams.get()[1].name, [0x61, 0xd800, 0, 0xffff]);
        let f = v
            .open_stream(id, &streams.get()[1].name, stream_limits(), &r)
            .unwrap();
        assert_eq!(f.identity(), id);
        let before = source.reads.load(Ordering::Relaxed);
        let mut b = [0; 32];
        assert_eq!(f.read_at(0, &mut b, &r).unwrap(), 10);
        assert_eq!(&b[..10], b"secret-ads");
        assert_eq!(source.reads.load(Ordering::Relaxed), before);
        assert!(v.open_stream(id, &[0x41], stream_limits(), &r).is_err());
    }
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn resident_extension_ads_resolved_by_exact_instance_and_reference() {
    let r = r();
    let source = Arc::new(Image::new(ads_fixture(true, false)));
    {
        let v = NtfsVolume::open(source, limits(), &r).unwrap();
        let mut id = v.record(3, &r).unwrap().identity().clone();
        id.native = 24u64.to_le_bytes().to_vec();
        let streams = v.data_streams(&id, stream_limits(), &r).unwrap();
        assert_eq!(streams.get().len(), 2);
        let f = v
            .open_stream(&id, &[0x61, 0xd800, 0, 0xffff], stream_limits(), &r)
            .unwrap();
        let mut b = [0; 10];
        assert_eq!(f.read_at(0, &mut b, &r).unwrap(), 10);
        assert_eq!(&b, b"secret-ads");
    }
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn two_extension_nonresident_ads_large_indexed_reads_no_metadata_rescans() {
    let r = r();
    let source = Arc::new(Image::new(ads_fixture(true, true)));
    {
        let v = NtfsVolume::open(source.clone(), limits(), &r).unwrap();
        let mut id = v.record(3, &r).unwrap().identity().clone();
        id.native = 24u64.to_le_bytes().to_vec();
        let streams = v.data_streams(&id, stream_limits(), &r).unwrap();
        assert_eq!(streams.get()[1].segments, 2);
        assert_eq!(streams.get()[1].length, 131089);
        assert_eq!(streams.get()[1].initialized, 130001);
        let f = v
            .open_stream(&id, &[0x61, 0xd800, 0, 0xffff], stream_limits(), &r)
            .unwrap();
        let before = source.reads.load(Ordering::Relaxed);
        for i in 0..128 {
            let at = (i * 997) % 129000;
            let mut b = [0; 7];
            assert_eq!(f.read_at(at, &mut b, &r).unwrap(), 7);
            for (n, byte) in b.iter().enumerate() {
                let offset = at as usize + n;
                assert_eq!(*byte, (offset.wrapping_mul(31) + offset / 53) as u8);
            }
        }
        assert_eq!(source.reads.load(Ordering::Relaxed) - before, 128);
        let mut full = vec![0; f.len() as usize];
        assert_eq!(f.read_at(0, &mut full, &r).unwrap(), full.len());
        for (i, byte) in full.iter().enumerate() {
            assert_eq!(
                *byte,
                if i >= 130001 {
                    0
                } else {
                    (i.wrapping_mul(31) + i / 53) as u8
                }
            );
        }
        let before = source.reads.load(Ordering::Relaxed);
        let mut b = [0; 7];
        assert_eq!(f.read_at(f.len(), &mut b, &r).unwrap(), 0);
        assert_eq!(source.reads.load(Ordering::Relaxed), before);
    }
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn malformed_extension_bindings_and_vcn_semantics_fail_without_leaks() {
    let original = ads_fixture(true, true);
    let list = 2048 + 24 * 1024 + 56 + 96 + 24;
    let mutations: Vec<(usize, Vec<u8>, ErrorKind)> = vec![
        (
            2048 + 26 * 1024 + 32,
            (25u64 | (7 << 48)).to_le_bytes().to_vec(),
            ErrorKind::InvalidData,
        ),
        (
            2048 + 26 * 1024 + 16,
            8u16.to_le_bytes().to_vec(),
            ErrorKind::StalePlan,
        ),
        (
            list + 64 + 24,
            88u16.to_le_bytes().to_vec(),
            ErrorKind::InvalidData,
        ),
        (
            list + 64 + 8,
            1u64.to_le_bytes().to_vec(),
            ErrorKind::InvalidData,
        ),
        (
            2048 + 27 * 1024 + 56 + 80,
            vec![0x21, 97, 200, 0, 0],
            ErrorKind::InvalidData,
        ),
        (
            2048 + 24 * 1024 + 56 + 96 + 16,
            143u32.to_le_bytes().to_vec(),
            ErrorKind::InvalidData,
        ),
    ];
    for (at, value, expected) in mutations {
        let mut bytes = original.clone();
        bytes[at..at + value.len()].copy_from_slice(&value);
        let r = r();
        {
            let v = NtfsVolume::open(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
            let mut id = v.record(3, &r).unwrap().identity().clone();
            id.native = 24u64.to_le_bytes().to_vec();
            assert_eq!(
                v.open_stream(&id, &[0x61, 0xd800, 0, 0xffff], stream_limits(), &r)
                    .err()
                    .unwrap()
                    .kind,
                expected,
                "at={at}"
            );
        }
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn stream_aggregate_limits_cancel_and_stale_owners_refund() {
    let r = r();
    let source = Arc::new(Image::new(ads_fixture(true, true)));
    let v = NtfsVolume::open(source.clone(), limits(), &r).unwrap();
    let mut id = v.record(3, &r).unwrap().identity().clone();
    id.native = 24u64.to_le_bytes().to_vec();
    let retained = r.memory.used();
    for selected in [
        partmgr::fs_ntfs::NtfsStreamLimits {
            extension_records: 1,
            ..stream_limits()
        },
        partmgr::fs_ntfs::NtfsStreamLimits {
            list_entries: 3,
            ..stream_limits()
        },
        partmgr::fs_ntfs::NtfsStreamLimits {
            list_bytes: 63,
            ..stream_limits()
        },
        partmgr::fs_ntfs::NtfsStreamLimits {
            attributes: 2,
            ..stream_limits()
        },
        partmgr::fs_ntfs::NtfsStreamLimits {
            runs: 1,
            ..stream_limits()
        },
        partmgr::fs_ntfs::NtfsStreamLimits {
            work: 0,
            ..stream_limits()
        },
    ] {
        assert_eq!(
            v.open_stream(&id, &[0x61, 0xd800, 0, 0xffff], selected, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(r.memory.used(), retained);
    }
    let mut stale = id.clone();
    stale.generation += 1;
    assert_eq!(
        v.data_streams(&stale, stream_limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::StalePlan
    );
    let other = NtfsVolume::open(source.clone(), limits(), &r).unwrap();
    assert_eq!(
        other
            .open_stream(&id, &[], stream_limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::StalePlan
    );
    drop(other);
    let f = v
        .open_stream(&id, &[0x61, 0xd800, 0, 0xffff], stream_limits(), &r)
        .unwrap();
    let before = source.reads.load(Ordering::Relaxed);
    r.cancellation.cancel();
    let mut b = [0; 1];
    assert_eq!(
        f.read_at(f.len(), &mut b, &r).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(source.reads.load(Ordering::Relaxed), before);
    drop(f);
    drop(v);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn native_attribute_provenance_and_distinct_si_filename_times() {
    let r = r();
    let mut bytes = ads_fixture(true, false);
    let value = 2048 + 24 * 1024 + 56 + 24;
    for (i, ticks) in [11u64, 22, 33, 44].iter().enumerate() {
        q(&mut bytes, value + i * 8, *ticks);
    }
    d(&mut bytes, value + 52, 1234);
    let v = NtfsVolume::open(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
    let mut id = v.record(3, &r).unwrap().identity().clone();
    id.native = 24u64.to_le_bytes().to_vec();
    let attrs = v.native_attributes(&id, stream_limits(), &r).unwrap();
    assert_eq!(attrs.get().len(), 4);
    let si = attrs
        .get()
        .iter()
        .find_map(|a| a.standard_information())
        .unwrap();
    assert_eq!(si.timestamps, [11, 22, 33, 44]);
    assert_eq!(si.security_id, Some(1234));
    assert_eq!(si.raw.len(), 72);
    let ads = attrs
        .get()
        .iter()
        .find(|a| a.name == [0x61, 0xd800, 0, 0xffff])
        .unwrap();
    assert_eq!(ads.owner, id);
    assert_eq!(ads.record.native, 26u64.to_le_bytes());
    assert_eq!(ads.offset, 56);
    assert_eq!(ads.kind, 0x80);
    assert_eq!(ads.instance, 9);
    drop(attrs);
    drop(v);
    assert_eq!(r.memory.used(), 0);
    let r = Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    };
    let mut bytes = fixture();
    let value = 2048 + 24 * 1024 + 56 + 72 + 24;
    for (i, ticks) in [101u64, 202, 303, 404].iter().enumerate() {
        q(&mut bytes, value + 8 + i * 8, *ticks);
    }
    let v = NtfsVolume::open(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
    let record = v.record(24, &r).unwrap();
    assert_eq!(
        record.native_standard_information().unwrap().timestamps,
        [0; 4]
    );
    let names = record.native_file_names().collect::<Vec<_>>();
    assert_eq!(names[0].timestamps, [101, 202, 303, 404]);
}

#[test]
fn generic_metadata_preserves_mft_change_filetime_and_refunds() {
    let r = r();
    let mut bytes = ads_fixture(false, false);
    let value = 2048 + 24 * 1024 + 56 + 24;
    q(&mut bytes, value + 16, u64::MAX);
    let volume = NtfsVolume::open(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
    let record = volume.record(24, &r).unwrap();
    let baseline = r.memory.used();
    let metadata = record.metadata(&r).unwrap();
    let (_, changed) = metadata
        .get()
        .attributes
        .iter()
        .find(|(name, _)| {
            name == &NativeName::Bytes(b"ntfs.STANDARD_INFORMATION.mft_changed.FILETIME".to_vec())
        })
        .unwrap();
    assert_eq!(
        changed,
        &partmgr::fs_core::MetadataField::Known(u64::MAX.to_le_bytes().to_vec())
    );
    drop(metadata);
    assert_eq!(r.memory.used(), baseline);
    drop((record, volume));
    assert_eq!(r.memory.used(), 0);
}
#[test]
#[ignore = "explicit isolated ADS gate; requires NTFS3G_BIN, TSK_BIN, PARTMGR_NTFS_STREAM_EVIDENCE; missing tools fail"]
fn native_ads_attribute_list_independent_oracles() {
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf, process::Command};
    let out = PathBuf::from(
        std::env::var_os("PARTMGR_NTFS_STREAM_EVIDENCE").expect("required evidence destination"),
    );
    fs::create_dir(&out).expect("fresh destination required");
    let ntfs = PathBuf::from(std::env::var_os("NTFS3G_BIN").expect("required NTFS tools"));
    let tsk = PathBuf::from(std::env::var_os("TSK_BIN").expect("required independent TSK tools"));
    let source_files = [
        "Cargo.lock",
        "src/fs_ntfs.rs",
        "src/fs_ntfs_stream.rs",
        "src/fs_ntfs_bootstrap.rs",
        "src/fs_core.rs",
        "src/fs_file.rs",
        "src/storage.rs",
        "tests/fs_ntfs.rs",
    ];
    let mut receipt = String::from(
        "scope=isolated immutable ADS/attribute-list reader; native tools do not establish Windows snapshot/replay/restore\n",
    );
    let mut bindings = Vec::new();
    fs::create_dir(out.join("sources")).unwrap();
    for file in source_files {
        let bytes = fs::read(file).unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let archived = out.join("sources").join(file);
        fs::create_dir_all(archived.parent().unwrap()).unwrap();
        fs::write(&archived, &bytes).unwrap();
        bindings.push((file, digest.clone()));
        receipt.push_str(&format!("source={file} sha256={digest}\n"));
    }
    let executable = std::env::current_exe().unwrap();
    let executable_bytes = fs::read(&executable).unwrap();
    fs::write(out.join("gate-binary"), &executable_bytes).unwrap();
    receipt.push_str(&format!(
        "binary_sha256={:x}\n",
        Sha256::digest(&executable_bytes)
    ));
    let mut command_count = 0;
    let mut run = |tool: &std::path::Path, args: Vec<String>| {
        let result = Command::new(tool)
            .args(&args)
            .output()
            .unwrap_or_else(|e| panic!("required {}: {e}", tool.display()));
        let label = format!("command-{command_count:03}");
        command_count += 1;
        fs::write(out.join(format!("{label}.stdout")), &result.stdout).unwrap();
        fs::write(out.join(format!("{label}.stderr")), &result.stderr).unwrap();
        receipt.push_str(&format!(
            "command={} {args:?}\nexit={} stdout={label}.stdout stderr={label}.stderr\n",
            tool.display(),
            result.status
        ));
        fs::write(out.join("receipt.txt"), &receipt).unwrap();
        assert!(
            result.status.success(),
            "{}: {}",
            tool.display(),
            String::from_utf8_lossy(&result.stderr)
        );
        result.stdout
    };
    for name in ["mkntfs", "ntfscp", "ntfscat", "ntfsinfo"] {
        run(&ntfs.join(name), vec!["--version".into()]);
    }
    run(&tsk.join("fls"), vec!["-V".into()]);
    run(&tsk.join("icat"), vec!["-V".into()]);
    let image = out.join("native.ntfs");
    fs::File::create(&image).unwrap().set_len(64 << 20).unwrap();
    run(
        &ntfs.join("mkntfs"),
        vec![
            "-F".into(),
            "-Q".into(),
            "-s".into(),
            "512".into(),
            "-c".into(),
            "4096".into(),
            image.display().to_string(),
        ],
    );
    let base = out.join("base.bin");
    fs::write(&base, b"ordinary-base-data").unwrap();
    run(
        &ntfs.join("ntfscp"),
        vec![
            image.display().to_string(),
            base.display().to_string(),
            "/native.bin".into(),
        ],
    );
    let mut models = vec![(String::new(), b"ordinary-base-data".to_vec())];
    for index in 0..20 {
        let name = format!("Evidence-{index:03}");
        let length = if index == 19 { 131089 } else { 37 + index };
        let bytes = (0..length)
            .map(|i| ((i * 31 + i / 53 + index) % 251) as u8)
            .collect::<Vec<_>>();
        let path = out.join(format!("stream-{index:03}.bin"));
        fs::write(&path, &bytes).unwrap();
        run(
            &ntfs.join("ntfscp"),
            vec![
                "-N".into(),
                name.clone(),
                image.display().to_string(),
                path.display().to_string(),
                "/native.bin".into(),
            ],
        );
        models.push((name, bytes));
    }
    let listing = String::from_utf8(run(
        &tsk.join("fls"),
        vec!["-f".into(), "ntfs".into(), image.display().to_string()],
    ))
    .unwrap();
    let inode = listing
        .lines()
        .find(|line| line.ends_with(":\tnative.bin"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .trim_end_matches(':')
        .split('-')
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    run(
        &ntfs.join("ntfsinfo"),
        vec!["-i".into(), inode.to_string(), image.display().to_string()],
    );
    let original = fs::read(&image).unwrap();
    let image_hash = format!("{:x}", Sha256::digest(&original));
    let r = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let selected = partmgr::fs_ntfs::NtfsStreamLimits {
        extension_records: 64,
        list_entries: 256,
        list_bytes: 1 << 20,
        attributes: 256,
        runs: 512,
        work: 2_000_000,
    };
    let v = NtfsVolume::open_stream_profile(Arc::new(Image::new(original)), limits(), selected, &r)
        .unwrap();
    let owner = v.stream_identity(inode, &r).unwrap();
    let streams = v.data_streams(&owner, selected, &r).unwrap();
    assert_eq!(streams.get().len(), models.len());
    let metadata = v.native_attributes(&owner, selected, &r).unwrap();
    assert!(
        metadata.get().iter().any(|a| a.kind == 0x20),
        "native fixture must actually reach ATTRIBUTE_LIST"
    );
    assert!(
        metadata.get().iter().any(|a| a.record != owner),
        "native fixture must use extensions"
    );
    for (name, expected) in &models {
        let f = v
            .open_stream(
                &owner,
                &name.encode_utf16().collect::<Vec<_>>(),
                selected,
                &r,
            )
            .unwrap();
        let mut actual = vec![0; f.len() as usize];
        assert_eq!(f.read_at(0, &mut actual, &r).unwrap(), actual.len());
        assert_eq!(&actual, expected);
        let mut args = vec![image.display().to_string(), "/native.bin".into()];
        if !name.is_empty() {
            args.splice(0..0, ["-n".into(), name.clone()]);
        }
        let oracle = run(&ntfs.join("ntfscat"), args);
        assert_eq!(&oracle, expected);
        let native_leaf = if name.is_empty() {
            "native.bin".to_owned()
        } else {
            format!("native.bin:{name}")
        };
        let indexed = listing
            .lines()
            .find(|line| line.ends_with(&format!(":\t{native_leaf}")))
            .unwrap_or_else(|| panic!("missing TSK stream {native_leaf}: {listing}"));
        let reference = indexed
            .split_whitespace()
            .nth(1)
            .unwrap()
            .trim_end_matches(':');
        let independent = run(
            &tsk.join("icat"),
            vec![
                "-f".into(),
                "ntfs".into(),
                image.display().to_string(),
                reference.into(),
            ],
        );
        assert_eq!(&independent, expected);

        let label = if name.is_empty() { "unnamed" } else { name };
        fs::write(out.join(format!("decoded-{label}.bin")), &actual).unwrap();
    }
    drop(metadata);
    drop(streams);
    drop(v);
    assert_eq!(r.memory.used(), 0);
    drop(run);
    for (file, digest) in bindings {
        assert_eq!(
            format!("{:x}", Sha256::digest(fs::read(file).unwrap())),
            digest,
            "source changed"
        );
    }
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&image).unwrap())),
        image_hash
    );
    receipt.push_str(&format!("validated_streams={} image_sha256={image_hash} source_end_matches_start=true image_unchanged=true all_leases_refunded=true\n",models.len()));
    fs::write(out.join("receipt.txt"), receipt).unwrap();
}
#[test]
fn explicit_stream_profile_bootstraps_split_mft_and_keeps_classic_gate() {
    let original = fixture();
    let mut image = original.clone();
    image.resize(256 * 512, 0);
    q(&mut image, 40, 256);
    // Independently remap MFT logical bytes4096..32768 to a distinct physical run.
    image[100 * 512..100 * 512 + 32768 - 4096]
        .copy_from_slice(&original[2048 + 4096..2048 + 32768]);
    let mut first = nonresident(&[0x11, 8, 4, 0], 64, 32768, 32768, false);
    q(&mut first, 24, 7);
    let mut list = list_entry(0x80, &[], 0, 0, 7, 3);
    list.extend(list_entry(0x80, &[], 8, 2, 7, 9));
    let zero = record(0, &[resident(0x20, &list, 4), first]);
    image[2048..3072].copy_from_slice(&zero);
    let mut continuation = nonresident(&[0x11, 56, 100, 0], 56, 0, 0, false);
    q(&mut continuation, 16, 8);
    q(&mut continuation, 24, 63);
    w(&mut continuation, 14, 9);
    let mut extension = record(2, &[continuation]);
    q(&mut extension, 32, 7 << 48);
    image[2048 + 2048..2048 + 3072].copy_from_slice(&extension);
    let r = r();
    let source = Arc::new(Image::new(image));
    assert_eq!(
        NtfsVolume::open(source.clone(), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Unsupported
    );
    assert_eq!(r.memory.used(), 0);
    let before = source.reads.load(Ordering::Relaxed);
    assert_eq!(
        NtfsVolume::open_stream_profile(
            source.clone(),
            limits(),
            partmgr::fs_ntfs::NtfsStreamLimits {
                work: 1,
                ..stream_limits()
            },
            &r
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::BudgetExhausted
    );
    // Boot and initial FILE only: the extension is never fetched.
    assert_eq!(source.reads.load(Ordering::Relaxed) - before, 2);
    assert_eq!(r.memory.used(), 0);
    for capped in [
        partmgr::fs_ntfs::NtfsStreamLimits {
            attributes: 1,
            ..stream_limits()
        },
        partmgr::fs_ntfs::NtfsStreamLimits {
            runs: 1,
            ..stream_limits()
        },
    ] {
        assert_eq!(
            NtfsVolume::open_stream_profile(source.clone(), limits(), capped, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(r.memory.used(), 0);
    }
    {
        let v = NtfsVolume::open_stream_profile(source, limits(), stream_limits(), &r).unwrap();
        assert_eq!(v.record_count(), 32);
        let file = v.open_file(24, &r).unwrap();
        let mut bytes = [0; 5];
        assert_eq!(file.read_at(0, &mut bytes, &r).unwrap(), 5);
        assert_eq!(&bytes, b"hello");
        let owner = v.stream_identity(0, &r).unwrap();
        let metadata = v.native_attributes(&owner, stream_limits(), &r).unwrap();
        assert_eq!(metadata.get().len(), 3);
        assert!(
            metadata
                .get()
                .iter()
                .any(|a| a.record.native == 2u64.to_le_bytes())
        );
    }
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn fresh_native_attribute_selectors_are_scoped_and_do_not_accept_caller_maps() {
    let mut image = fixture();
    let mut index = named_resident(&[0x24, 0x53, 0x49, 0x49], b"index-evidence", 9);
    d(&mut index, 0, 0x90);
    let encoded = record(
        24,
        &[
            resident(0x10, &[0; 72], 1),
            resident(0x50, b"security-evidence", 4),
            resident(0x80, b"base", 3),
            index,
        ],
    );
    image[2048 + 24 * 1024..2048 + 25 * 1024].copy_from_slice(&encoded);
    let r = r();
    let source = Arc::new(Image::new(image));
    {
        let v = NtfsVolume::open(source.clone(), limits(), &r).unwrap();
        let owner = v.stream_identity(24, &r).unwrap();
        let f = v
            .open_native_attribute_stream(&owner, 0x50, &[], stream_limits(), &r)
            .unwrap();
        let before = source.reads.load(Ordering::Relaxed);
        let mut b = [0; 17];
        assert_eq!(f.read_at(0, &mut b, &r).unwrap(), 17);
        assert_eq!(&b, b"security-evidence");
        assert_eq!(source.reads.load(Ordering::Relaxed), before);
        let index = v
            .open_native_attribute_stream(
                &owner,
                0x90,
                &[0x24, 0x53, 0x49, 0x49],
                stream_limits(),
                &r,
            )
            .unwrap();
        let mut b = [0; 14];
        assert_eq!(index.read_at(0, &mut b, &r).unwrap(), 14);
        assert_eq!(&b, b"index-evidence");
        assert_eq!(index.identity(), &owner);
        assert_eq!(
            v.open_native_attribute_stream(&owner, 0x30, &[], stream_limits(), &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::Unsupported
        );
        let mut stale = owner;
        stale.generation += 1;
        assert_eq!(
            v.open_native_attribute_stream(&stale, 0x50, &[], stream_limits(), &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::StalePlan
        );
    }
    assert_eq!(r.memory.used(), 0);
}

/// Explicit independent native fixture gate; enabled missing inputs fail.
#[test]
#[ignore = "requires externally generated NTFS MFT attribute-list fixture and native MFT dump"]
fn native_mft_attribute_list_bootstrap_matches_independent_dump() {
    let image =
        std::env::var("PARTMGR_NTFS_BOOTSTRAP_NATIVE_IMAGE").expect("native image path required");
    let expected =
        std::env::var("PARTMGR_NTFS_BOOTSTRAP_NATIVE_MFT").expect("native MFT dump path required");
    let bytes = std::fs::read(image).unwrap();
    let expected = std::fs::read(expected).unwrap();
    let source = Arc::new(Image::new(bytes));
    let r = r();
    {
        let volume =
            NtfsVolume::open_stream_profile(source.clone(), limits(), stream_limits(), &r).unwrap();
        let owner = volume.stream_identity(0, &r).unwrap();
        let attributes = volume
            .native_attributes(&owner, stream_limits(), &r)
            .unwrap();
        assert!(
            attributes
                .get()
                .iter()
                .any(|a| a.kind == 0xb0 && a.record != owner)
        );
        assert_eq!(
            attributes.get().iter().filter(|a| a.kind == 0x80).count(),
            2
        );
        assert!(
            attributes
                .get()
                .iter()
                .any(|a| a.kind == 0x80 && a.record != owner)
        );
        let file = volume
            .open_stream(&owner, &[], stream_limits(), &r)
            .unwrap();
        assert_eq!(file.len(), expected.len() as u64);
        let mut buffer = [0; 1031];
        let mut actual = Vec::new();
        let mut at = 0;
        while at < expected.len() {
            let n = file.read_at(at as u64, &mut buffer, &r).unwrap();
            assert!(n > 0);
            actual.extend_from_slice(&buffer[..n]);
            at += n;
        }
        // ntfscat exposes the MFT after native USA fixups, not raw sector tails.
        for record in actual.chunks_exact_mut(1024) {
            let usa = usize::from(u16::from_le_bytes([record[4], record[5]]));
            for sector in 1..=2 {
                let saved = [record[usa + sector * 2], record[usa + sector * 2 + 1]];
                record[sector * 512 - 2..sector * 512].copy_from_slice(&saved);
            }
        }
        assert!(
            actual == expected,
            "complete USA-normalized native MFT bytes"
        );
    }
    assert_eq!(r.memory.used(), 0);
    // Independent native record offsets: the known first MFT extent contains slot16.
    let cluster = usize::from(u16::from_le_bytes([source.bytes[11], source.bytes[12]]))
        * usize::from(source.bytes[13]);
    let mft_cluster = u64::from_le_bytes(source.bytes[48..56].try_into().unwrap());
    let extension = mft_cluster as usize * cluster + 16 * 1024;
    let mut data = extension
        + usize::from(u16::from_le_bytes(
            source.bytes[extension + 20..extension + 22]
                .try_into()
                .unwrap(),
        ));
    while u32::from_le_bytes(source.bytes[data..data + 4].try_into().unwrap()) != 0x80 {
        let length =
            u32::from_le_bytes(source.bytes[data + 4..data + 8].try_into().unwrap()) as usize;
        assert!(length >= 24);
        data += length;
        assert!(data < extension + 1024);
    }
    let pairs = data
        + usize::from(u16::from_le_bytes(
            source.bytes[data + 32..data + 34].try_into().unwrap(),
        ));
    assert_eq!(source.bytes[pairs], 0x11);
    for (case, kind) in [
        (0, ErrorKind::StalePlan),
        (1, ErrorKind::InvalidData),
        (2, ErrorKind::InvalidData),
        (3, ErrorKind::InvalidData),
    ] {
        let mut malformed = source.bytes.clone();
        match case {
            0 => w(&mut malformed, extension + 16, 2),
            1 => q(&mut malformed, extension + 32, (1 << 48) | 1),
            2 => q(&mut malformed, data + 16, 7),
            3 => malformed[pairs + 2] = mft_cluster as u8,
            _ => unreachable!(),
        }
        let error = NtfsVolume::open_stream_profile(
            Arc::new(Image::new(malformed)),
            limits(),
            stream_limits(),
            &r,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind, kind, "native malformed extension case {case}");
        assert_eq!(r.memory.used(), 0);
    }
}
