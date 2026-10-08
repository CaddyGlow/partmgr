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
fn w(b: &mut [u8], p: usize, n: u16) {
    b[p..p + 2].copy_from_slice(&n.to_le_bytes());
}
fn d(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
fn q(b: &mut [u8], p: usize, n: u64) {
    b[p..p + 8].copy_from_slice(&n.to_le_bytes());
}
// These bytes describe a separate hand-authored disk layout, without production builders.
fn resident(kind: u32, value: &[u8], id: u16) -> Vec<u8> {
    let mut a = vec![0; (24 + value.len()).next_multiple_of(8)];
    let n = a.len();
    d(&mut a, 0, kind);
    d(&mut a, 4, n as u32);
    w(&mut a, 14, id);
    d(&mut a, 16, value.len() as u32);
    w(&mut a, 20, 24);
    a[24..24 + value.len()].copy_from_slice(value);
    a
}
fn nonresident(
    mapping: &[u8],
    clusters: u64,
    length: u64,
    initialized: u64,
    sparse: bool,
) -> Vec<u8> {
    let h = if sparse { 72 } else { 64 };
    let mut a = vec![0; (h + mapping.len()).next_multiple_of(8)];
    let n = a.len();
    d(&mut a, 0, 0x80);
    d(&mut a, 4, n as u32);
    a[8] = 1;
    w(&mut a, 12, if sparse { 0x8000 } else { 0 });
    w(&mut a, 14, 3);
    q(&mut a, 24, clusters - 1);
    w(&mut a, 32, h as u16);
    q(&mut a, 40, clusters * 512);
    q(&mut a, 48, length);
    q(&mut a, 56, initialized);
    if sparse {
        q(&mut a, 64, (clusters - 1) * 512);
    }
    a[h..h + mapping.len()].copy_from_slice(mapping);
    a
}
fn record(number: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..4].copy_from_slice(b"FILE");
    w(&mut b, 4, 48);
    w(&mut b, 6, 3);
    w(&mut b, 16, 7);
    w(&mut b, 18, 1);
    w(&mut b, 20, 56);
    w(&mut b, 22, 1);
    d(&mut b, 28, 1024);
    d(&mut b, 44, number);
    let mut at = 56;
    for a in attrs {
        b[at..at + a.len()].copy_from_slice(a);
        at += a.len();
    }
    d(&mut b, at, u32::MAX);
    d(&mut b, 24, (at + 4) as u32);
    w(&mut b, 48, 0xa55a);
    for i in 1..=2 {
        let p = i * 512 - 2;
        let old = u16::from_le_bytes([b[p], b[p + 1]]);
        w(&mut b, 48 + i * 2, old);
        w(&mut b, p, 0xa55a);
    }
    b
}
fn fixture() -> Vec<u8> {
    let mut b = vec![0; 128 * 512];
    b[3..11].copy_from_slice(b"NTFS    ");
    w(&mut b, 11, 512);
    b[13] = 1;
    q(&mut b, 40, 128);
    q(&mut b, 48, 4);
    q(&mut b, 56, 100);
    b[64] = (-10i8) as u8;
    b[68] = (-10i8) as u8;
    w(&mut b, 510, 0xaa55);
    let mft = nonresident(&[0x11, 64, 4, 0], 64, 32768, 32768, false);
    let mut vol = vec![0; 12];
    vol[8] = 3;
    vol[9] = 1;
    let mut name = vec![0; 70];
    q(&mut name, 0, 5 | (7 << 48));
    name[64] = 2;
    name[65] = 1;
    w(&mut name, 66, 0x65e5);
    w(&mut name, 68, 0xd800);
    let attrs = vec![
        resident(0x10, &[0; 48], 1),
        resident(0x30, &name, 2),
        resident(0x80, b"hello", 3),
    ];
    for (n, a) in [
        (0, vec![mft]),
        (3, vec![resident(0x70, &vol, 1)]),
        (24, attrs),
        (
            25,
            vec![nonresident(
                &[0x11, 1, 90, 0x01, 1, 0x11, 1, 1, 0],
                3,
                1536,
                1280,
                true,
            )],
        ),
    ] {
        let p = 2048 + n * 1024;
        b[p..p + 1024].copy_from_slice(&record(n as u32, &a));
    }
    b[90 * 512..91 * 512].fill(0x31);
    b[91 * 512..92 * 512].fill(0x72);
    b
}
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
