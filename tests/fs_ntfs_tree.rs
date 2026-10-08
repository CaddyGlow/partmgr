use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, NativeName, Resources, StreamKind, TreeSource},
    fs_ntfs::{NtfsDirectoryLimits, NtfsReadLimits, NtfsVolume},
    fs_ntfs_tree::{NtfsTreePolicy, NtfsTreeSource},
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
fn base_fixture() -> Vec<u8> {
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
fn name_value(name: &str, parent: u64) -> Vec<u8> {
    let units = name.encode_utf16().collect::<Vec<_>>();
    let mut v = vec![0; 66 + 2 * units.len()];
    q(&mut v, 0, parent | (7 << 48));
    v[64] = units.len() as u8;
    v[65] = 1;
    for (i, c) in units.into_iter().enumerate() {
        w(&mut v, 66 + 2 * i, c);
    }
    v
}
fn index_entry(number: u64, name: &str, child: Option<u64>) -> Vec<u8> {
    let v = name_value(name, 5);
    let n = (16 + v.len() + usize::from(child.is_some()) * 8).next_multiple_of(8);
    let mut b = vec![0; n];
    q(&mut b, 0, number | (7 << 48));
    w(&mut b, 8, n as u16);
    w(&mut b, 10, v.len() as u16);
    w(&mut b, 12, u16::from(child.is_some()));
    b[16..16 + v.len()].copy_from_slice(&v);
    if let Some(c) = child {
        q(&mut b, n - 8, c);
    }
    b
}
fn terminal(child: Option<u64>) -> Vec<u8> {
    let n = if child.is_some() { 24 } else { 16 };
    let mut b = vec![0; n];
    w(&mut b, 8, n as u16);
    w(&mut b, 12, 2 | u16::from(child.is_some()));
    if let Some(c) = child {
        q(&mut b, 16, c);
    }
    b
}
fn root_attribute(entries: &[Vec<u8>], large: bool) -> Vec<u8> {
    let n = 32 + entries.iter().map(Vec::len).sum::<usize>();
    let mut v = vec![0; n];
    d(&mut v, 0, 0x30);
    d(&mut v, 4, 1);
    d(&mut v, 8, 1024);
    v[12] = 2;
    d(&mut v, 16, 16);
    d(&mut v, 20, (n - 16) as u32);
    d(&mut v, 24, (n - 16) as u32);
    d(&mut v, 28, u32::from(large));
    let mut at = 32;
    for e in entries {
        v[at..at + e.len()].copy_from_slice(e);
        at += e.len();
    }
    named_resident(0x90, &v, 1)
}
fn named_resident(kind: u32, value: &[u8], id: u16) -> Vec<u8> {
    let mut a = resident(kind, &[vec![0; 8], value.to_vec()].concat(), id);
    a[9] = 4;
    w(&mut a, 10, 24);
    d(&mut a, 16, value.len() as u32);
    w(&mut a, 20, 32);
    a[24..32].copy_from_slice(&[36, 0, 73, 0, 51, 0, 48, 0]);
    a
}
fn fixture() -> Vec<u8> {
    let mut b = base_fixture();
    b.resize(512 * 1024, 0);
    q(&mut b, 40, 1024);
    let up = nonresident(&[0x22, 0, 1, 0x80, 0, 0], 256, 131072, 131072, false);
    let p = 2048 + 10 * 1024;
    b[p..p + 1024].copy_from_slice(&record(10, &[up]));
    for c in 0..65536u32 {
        let upper = if (97..=122).contains(&c) { c - 32 } else { c };
        w(&mut b, 128 * 512 + c as usize * 2, upper as u16);
    }
    let p = 2048 + 5 * 1024;
    let mut root = record(
        5,
        &[root_attribute(
            &[
                index_entry(24, "alpha", None),
                index_entry(24, "beta", None),
                terminal(None),
            ],
            false,
        )],
    );
    w(&mut root, 22, 3);
    b[p..p + 1024].copy_from_slice(&root);
    let attrs = [
        resident(0x30, &name_value("alpha", 5), 1),
        resident(0x30, &name_value("beta", 5), 2),
        resident(0x80, b"hello", 3),
    ];
    let p = 2048 + 24 * 1024;
    b[p..p + 1024].copy_from_slice(&record(24, &attrs));
    b
}
fn index_limits() -> NtfsDirectoryLimits {
    NtfsDirectoryLimits {
        blocks: 32,
        entries: 128,
        depth: 8,
    }
}
#[test]
fn native_index_hardlinks_pages_deferred_and_refunds() {
    let r = r();
    let image = Arc::new(Image::new(fixture()));
    {
        let volume = NtfsVolume::open(image.clone(), limits(), &r).unwrap();
        let root = volume.root_identity(&r).unwrap();
        let dir = volume.directory(&root, index_limits(), &r).unwrap();
        assert_eq!(dir.entries().len(), 2);
        assert_eq!(dir.entries()[0].identity, dir.entries()[1].identity);
        drop(dir);
        let tree = NtfsTreeSource::inventory(volume, 8, 8, index_limits(), &r).unwrap();
        let page = tree.directory_page(&tree.root(), None, 1, &r).unwrap();
        assert_eq!(
            page.entries[0].name,
            NativeName::Utf16("alpha".encode_utf16().collect())
        );
        let next = tree
            .directory_page(&tree.root(), page.next.as_deref(), 1, &r)
            .unwrap();
        assert_eq!(page.entries[0].object, next.entries[0].object);
        let file = tree
            .open_stream(&page.entries[0].object, &StreamKind::Data, &r)
            .unwrap();
        drop(tree);
        let mut b = [0; 5];
        assert_eq!(file.read_at(0, &mut b, &r).unwrap(), 5);
        assert_eq!(&b, b"hello");
    }
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn index_parent_target_order_and_limits_fail() {
    for offset in [
        2048 + 5 * 1024 + 56 + 32 + 32 + 16,
        2048 + 5 * 1024 + 56 + 32 + 32 + 6,
        2048 + 5 * 1024 + 56 + 32 + 20,
    ] {
        let mut b = fixture();
        b[offset] = 0xff;
        let r = r();
        let v = NtfsVolume::open(Arc::new(Image::new(b)), limits(), &r).unwrap();
        let root = v.root_identity(&r).unwrap();
        assert!(v.directory(&root, index_limits(), &r).is_err());
    }
    let r = r();
    let v = NtfsVolume::open(Arc::new(Image::new(fixture())), limits(), &r).unwrap();
    let root = v.root_identity(&r).unwrap();
    let baseline = r.memory.used();
    let mut cap = index_limits();
    cap.entries = 1;
    assert_eq!(
        v.directory(&root, cap, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), baseline);
    r.cancellation.cancel();
    assert_eq!(
        v.directory(&root, index_limits(), &r).err().unwrap().kind,
        ErrorKind::Cancelled
    );
}
#[test]
#[ignore = "explicit native large-directory gate requires NTFS tools and PARTMGR_NTFS_TREE_EVIDENCE"]
fn native_large_directory() {
    use sha2::{Digest, Sha256};
    use std::{fs, process::Command};
    let out = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_NTFS_TREE_EVIDENCE").expect("evidence required"),
    );
    fs::create_dir(&out).unwrap();
    let mut receipt = format!(
        "reader_sha256={:x}\ntree_sha256={:x}\nfixture_sha256={:x}\ntest_binary_sha256={:x}\n",
        Sha256::digest(include_bytes!("../src/fs_ntfs.rs")),
        Sha256::digest(include_bytes!("../src/fs_ntfs_tree.rs")),
        Sha256::digest(include_bytes!("fs_ntfs_tree.rs")),
        Sha256::digest(fs::read(std::env::current_exe().unwrap()).unwrap())
    );
    for tool in ["mkntfs", "ntfscp", "fls", "icat"] {
        let binary = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
            .expect("required tool");
        receipt.push_str(&format!(
            "tool={tool} path={} sha256={:x}\n",
            binary.display(),
            Sha256::digest(fs::read(&binary).unwrap())
        ));
    }

    let mut run = |tool: &str, args: Vec<String>| {
        let result = Command::new(tool)
            .args(&args)
            .output()
            .expect("native tool required");
        let n = receipt.matches("command=").count();
        fs::write(out.join(format!("{n}-{tool}.stdout")), &result.stdout).unwrap();
        fs::write(out.join(format!("{n}-{tool}.stderr")), &result.stderr).unwrap();
        receipt.push_str(&format!(
            "command={tool} {args:?} status={}\n",
            result.status
        ));
        fs::write(out.join("receipt.txt"), &receipt).unwrap();
        assert!(
            result.status.success(),
            "{tool}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        result.stdout
    };
    let image = out.join("native.ntfs");
    fs::File::create(&image).unwrap().set_len(64 << 20).unwrap();
    run("mkntfs", vec!["--version".into()]);
    run("fls", vec!["-V".into()]);
    run("ntfscp", vec!["--version".into()]);
    run("icat", vec!["-V".into()]);
    run("uname", vec!["-a".into()]);
    run(
        "mkntfs",
        vec!["-F".into(), "-Q".into(), image.display().to_string()],
    );
    let payload = out.join("payload");
    fs::write(&payload, b"native index payload").unwrap();
    for i in 0..96 {
        run(
            "ntfscp",
            vec![
                image.display().to_string(),
                payload.display().to_string(),
                format!("/file-{i:03}.txt"),
            ],
        );
    }
    let bytes = fs::read(&image).unwrap();
    let before = format!("{:x}", Sha256::digest(&bytes));
    let listing = String::from_utf8(run(
        "fls",
        vec!["-f".into(), "ntfs".into(), image.display().to_string()],
    ))
    .unwrap();
    let r = r();
    let source = Arc::new(Image::new(bytes));
    let v = NtfsVolume::open(source.clone(), limits(), &r).unwrap();
    let root = v.root_identity(&r).unwrap();
    let directory = v.directory(&root, index_limits(), &r).unwrap();
    assert!(directory.entries().len() >= 96);
    assert_eq!(
        NtfsTreeSource::inventory(
            NtfsVolume::open(source, limits(), &r).unwrap(),
            128,
            8,
            index_limits(),
            &r
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Unsupported
    );
    let tree = NtfsTreeSource::inventory_with_policy(
        v,
        128,
        8,
        index_limits(),
        NtfsTreePolicy::UserNamespace,
        &r,
    )
    .unwrap();
    let page = tree.directory_page(&tree.root(), None, 128, &r).unwrap();
    assert_eq!(page.entries.len(), 96);
    assert!(!tree.excluded_entries().is_empty());
    assert!(
        tree.metadata(&tree.root(), &r)
            .unwrap()
            .attributes
            .iter()
            .any(|(name, _)| *name
                == NativeName::Bytes(b"ntfs.capture.excluded-root-metadata".to_vec()))
    );
    for i in 0..96 {
        let name = format!("file-{i:03}.txt");
        let e = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Utf16(name.encode_utf16().collect()))
            .unwrap();
        let line = listing
            .lines()
            .find(|s| s.ends_with(&format!(":\t{name}")))
            .unwrap();
        let reference = line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .trim_end_matches(':');
        assert_eq!(
            u64::from_le_bytes(e.object.native.as_slice().try_into().unwrap()),
            reference.split('-').next().unwrap().parse::<u64>().unwrap()
        );
        if i % 31 == 0 {
            let oracle = run("icat", vec![image.display().to_string(), reference.into()]);
            assert_eq!(oracle, b"native index payload");
            let f = tree.open_stream(&e.object, &StreamKind::Data, &r).unwrap();
            let mut got = [0; 20];
            assert_eq!(f.read_at(0, &mut got, &r).unwrap(), 20);
            assert_eq!(&got, b"native index payload");
        }
    }
    assert_eq!(
        before,
        format!("{:x}", Sha256::digest(fs::read(&image).unwrap()))
    );
    for e in directory.entries() {
        receipt.push_str(&format!(
            "native_root_name={:?} namespace={} identity={:?}\n",
            e.name, e.namespace, e.identity
        ));
    }
    for e in tree.excluded_entries() {
        receipt.push_str(&format!(
            "excluded_root_name={:?} namespace={} identity={:?}\n",
            e.name, e.namespace, e.identity
        ));
    }
    receipt.push_str(&format!("source_sha256={before}\nstatus=passed\n"));
    fs::write(out.join("receipt.txt"), receipt).unwrap();
}
fn allocation_fixture() -> Vec<u8> {
    let mut b = fixture();
    let mut alloc = nonresident(&[0x21, 2, 0x90, 1, 0], 2, 1024, 1024, false);
    alloc.resize(80, 0);
    alloc.copy_within(64..72, 72);
    alloc[64..72].copy_from_slice(&[36, 0, 73, 0, 51, 0, 48, 0]);
    d(&mut alloc, 0, 0xa0);
    d(&mut alloc, 4, 80);
    alloc[9] = 4;
    w(&mut alloc, 10, 64);
    w(&mut alloc, 32, 72);
    w(&mut alloc, 14, 2);
    let attrs = [
        root_attribute(&[terminal(Some(0))], true),
        alloc,
        named_resident(0xb0, &[1, 0, 0, 0, 0, 0, 0, 0], 3),
    ];
    let mut root = record(5, &attrs);
    w(&mut root, 22, 3);
    let p = 2048 + 5 * 1024;
    b[p..p + 1024].copy_from_slice(&root);
    let mut index = vec![0; 1024];
    index[..4].copy_from_slice(b"INDX");
    w(&mut index, 4, 40);
    w(&mut index, 6, 3);
    d(&mut index, 24, 24);
    d(&mut index, 32, 1000);
    let mut at = 48;
    for e in [
        index_entry(24, "alpha", None),
        index_entry(24, "beta", None),
        terminal(None),
    ] {
        index[at..at + e.len()].copy_from_slice(&e);
        at += e.len();
    }
    d(&mut index, 28, (at - 24) as u32);
    w(&mut index, 40, 0xa55a);
    for i in 1..=2 {
        let p = i * 512 - 2;
        let old = u16::from_le_bytes([index[p], index[p + 1]]);
        w(&mut index, 40 + i * 2, old);
        w(&mut index, p, 0xa55a);
    }
    b[400 * 512..402 * 512].copy_from_slice(&index);
    b
}
#[test]
fn allocation_bitmap_fixup_vcn_and_depth() {
    let r = r();
    let v = NtfsVolume::open(Arc::new(Image::new(allocation_fixture())), limits(), &r).unwrap();
    let root = v.root_identity(&r).unwrap();
    assert_eq!(
        v.directory(&root, index_limits(), &r)
            .unwrap()
            .entries()
            .len(),
        2
    );
    let baseline = r.memory.used();
    let mut caps = index_limits();
    caps.depth = 0;
    assert_eq!(
        v.directory(&root, caps, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), baseline);
    for p in [400 * 512 + 510, 400 * 512 + 16, 400 * 512 + 28] {
        let mut b = allocation_fixture();
        b[p] ^= 1;
        let v = NtfsVolume::open(Arc::new(Image::new(b)), limits(), &r).unwrap();
        let root = v.root_identity(&r).unwrap();
        assert_eq!(
            v.directory(&root, index_limits(), &r).err().unwrap().kind,
            ErrorKind::InvalidData
        );
    }
}
#[test]
fn child_cycles_collisions_and_tokens_are_rejected() {
    let mut b = allocation_fixture();
    let p = 400 * 512;
    b[p + 48..p + 1024].fill(0);
    let t = terminal(Some(0));
    b[p + 48..p + 72].copy_from_slice(&t);
    d(&mut b, p + 28, 48);
    d(&mut b, p + 36, 1);
    w(&mut b, p + 42, 0);
    w(&mut b, p + 44, 0);
    w(&mut b, p + 510, 0xa55a);
    w(&mut b, p + 1022, 0xa55a);
    let r = r();
    let v = NtfsVolume::open(Arc::new(Image::new(b)), limits(), &r).unwrap();
    let root = v.root_identity(&r).unwrap();
    assert_eq!(
        v.directory(&root, index_limits(), &r).err().unwrap().kind,
        ErrorKind::InvalidData
    );
    let mut b = fixture();
    let p = 2048 + 5 * 1024;
    let mut root = record(
        5,
        &[root_attribute(
            &[
                index_entry(24, "alpha", None),
                index_entry(24, "alpha", None),
                terminal(None),
            ],
            false,
        )],
    );
    w(&mut root, 22, 3);
    b[p..p + 1024].copy_from_slice(&root);
    let v = NtfsVolume::open(Arc::new(Image::new(b)), limits(), &r).unwrap();
    let root = v.root_identity(&r).unwrap();
    assert_eq!(
        v.directory(&root, index_limits(), &r).err().unwrap().kind,
        ErrorKind::InvalidData
    );
    let tree = NtfsTreeSource::inventory(
        NtfsVolume::open(Arc::new(Image::new(fixture())), limits(), &r).unwrap(),
        8,
        8,
        index_limits(),
        &r,
    )
    .unwrap();
    let first = tree.directory_page(&tree.root(), None, 1, &r).unwrap();
    let mut token = first.next.unwrap();
    token[0] ^= 1;
    assert_eq!(
        tree.directory_page(&tree.root(), Some(&token), 1, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::StalePlan
    );
    let metadata = tree.metadata(&first.entries[0].object, &r).unwrap();
    assert!(
        metadata
            .attributes
            .iter()
            .any(|(name, _)| *name == NativeName::Bytes(b"ntfs.FILE_NAME.occurrences".to_vec()))
    );
}
#[test]
fn special_directory_streams_and_index_io_budget_fail_explicitly() {
    let mut b = fixture();
    let p = 2048 + 5 * 1024;
    let mut root = record(
        5,
        &[
            resident(0x80, b"directory data", 2),
            root_attribute(
                &[
                    index_entry(24, "alpha", None),
                    index_entry(24, "beta", None),
                    terminal(None),
                ],
                false,
            ),
        ],
    );
    w(&mut root, 22, 3);
    b[p..p + 1024].copy_from_slice(&root);
    let r = r();
    assert_eq!(
        NtfsTreeSource::inventory(
            NtfsVolume::open(Arc::new(Image::new(b)), limits(), &r).unwrap(),
            8,
            8,
            index_limits(),
            &r
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Unsupported
    );
    let image = Arc::new(Image::new(allocation_fixture()));
    let v = NtfsVolume::open(image.clone(), limits(), &r).unwrap();
    let root = v.root_identity(&r).unwrap();
    let before = image.reads.load(Ordering::Relaxed);
    let small = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        v.directory(&root, index_limits(), &small)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(image.reads.load(Ordering::Relaxed), before);
    let baseline = r.memory.used();
    image.fail.store(400 * 512, Ordering::Relaxed);
    let error = v.directory(&root, index_limits(), &r).err().unwrap();
    assert_eq!(error.kind, ErrorKind::Io);
    assert!(error.source.is_some());
    assert_eq!(r.memory.used(), baseline);
}

#[test]
fn security_capture_preserves_root_and_hardlinked_file_descriptors() {
    use partmgr::{fs_core::MetadataField, fs_ntfs_security::*};
    let r = r();
    let mut bytes = fixture();
    let mut sd = vec![0; 40];
    sd[0] = 1;
    w(&mut sd, 2, 0x8004);
    d(&mut sd, 4, 20);
    d(&mut sd, 8, 20);
    d(&mut sd, 16, 32);
    sd[20..32].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    sd[32..40].copy_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
    let mut root = record(
        5,
        &[
            resident(0x50, &sd, 2),
            root_attribute(
                &[
                    index_entry(24, "alpha", None),
                    index_entry(24, "beta", None),
                    terminal(None),
                ],
                false,
            ),
        ],
    );
    w(&mut root, 22, 3);
    bytes[2048 + 5 * 1024..2048 + 6 * 1024].copy_from_slice(&root);
    let file = record(
        24,
        &[
            resident(0x30, &name_value("alpha", 5), 1),
            resident(0x30, &name_value("beta", 5), 2),
            resident(0x50, &sd, 3),
            resident(0x80, b"hello", 4),
        ],
    );
    bytes[2048 + 24 * 1024..2048 + 25 * 1024].copy_from_slice(&file);
    let volume = NtfsVolume::open(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
    let tree = NtfsTreeSource::inventory(volume, 8, 8, index_limits(), &r)
        .unwrap()
        .with_security_capture(
            NtfsSecureLimits {
                descriptor: NtfsSecurityLimits {
                    bytes: 8192,
                    aces: 32,
                    work: 256,
                },
                blocks: 8,
                entries: 64,
                depth: 8,
                work: 100000,
            },
            &r,
        )
        .unwrap();
    let page = tree.directory_page(&tree.root(), None, 8, &r).unwrap();
    assert_eq!(page.entries[0].object, page.entries[1].object);
    for id in [&tree.root(), &page.entries[0].object] {
        let baseline = r.memory.used();
        let metadata = tree.metadata(id, &r).unwrap();
        assert_eq!(metadata.get().security, MetadataField::Known(sd.clone()));
        assert_eq!(
            metadata.get().owner,
            MetadataField::Known(sd[20..32].to_vec())
        );
        drop(metadata);
        assert_eq!(r.memory.used(), baseline);
    }
    drop((page, tree));
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn security_capture_refuses_unknown_security_and_cancellation_without_leaks() {
    use partmgr::fs_ntfs_security::*;
    for cancelled in [false, true] {
        let r = r();
        let volume = NtfsVolume::open(Arc::new(Image::new(fixture())), limits(), &r).unwrap();
        let tree = NtfsTreeSource::inventory(volume, 8, 8, index_limits(), &r).unwrap();
        if cancelled {
            r.cancellation.cancel();
        }
        let error = tree
            .with_security_capture(
                NtfsSecureLimits {
                    descriptor: NtfsSecurityLimits {
                        bytes: 8192,
                        aces: 32,
                        work: 256,
                    },
                    blocks: 8,
                    entries: 64,
                    depth: 8,
                    work: 100000,
                },
                &r,
            )
            .err()
            .unwrap();
        assert_eq!(
            error.kind,
            if cancelled {
                ErrorKind::Cancelled
            } else {
                ErrorKind::Unsupported
            }
        );
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
#[ignore = "explicit native ACL tree capture gate requires image, tools and fresh evidence"]
fn native_security_tree_capture_exact_descriptor_oracle() {
    use partmgr::{fs_core::MetadataField, fs_ntfs_security::*};
    use sha2::{Digest, Sha256};
    use std::{fs, process::Command};
    let image = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_NTFS_ACL_TREE_IMAGE").expect("image required"),
    );
    let out = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_NTFS_ACL_TREE_EVIDENCE").expect("fresh evidence required"),
    );
    assert!(!out.exists());
    fs::create_dir(&out).unwrap();
    let tool = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_NTFSCAT").expect("pinned ntfscat required"),
    );
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
            "src/fs_ntfs_tree.rs",
            include_bytes!("../src/fs_ntfs_tree.rs"),
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
            "src/fs_ntfs_metadata.rs",
            include_bytes!("../src/fs_ntfs_metadata.rs"),
        ),
        (
            "tests/fs_ntfs_tree.rs",
            include_bytes!("../tests/fs_ntfs_tree.rs"),
        ),
    ];
    let archive = out.join("compiled-source");
    fs::create_dir(&archive).unwrap();
    let source_guard = |save: bool| {
        let mut bindings = String::new();
        for &(name, baked) in sources {
            assert_eq!(
                fs::read(name).unwrap(),
                baked,
                "compiled source mismatch: {name}"
            );
            bindings.push_str(&format!("{name} {:x}\n", Sha256::digest(baked)));
            if save {
                let path = archive.join(name);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, baked).unwrap();
            }
        }
        bindings
    };
    let bindings = source_guard(true);
    fs::write(out.join("source-start.sha256"), &bindings).unwrap();
    let binary = fs::read(std::env::current_exe().unwrap()).unwrap();
    fs::write(out.join("compiled-test"), &binary).unwrap();
    fs::write(
        out.join("binary.sha256"),
        format!("{:x}", Sha256::digest(&binary)),
    )
    .unwrap();
    let tool_bytes = fs::read(&tool).unwrap();
    fs::write(
        out.join("tool.sha256"),
        format!("{} {:x}", tool.display(), Sha256::digest(&tool_bytes)),
    )
    .unwrap();
    let original = fs::read(&image).unwrap();
    let source_hash = format!("{:x}", Sha256::digest(&original));
    fs::write(out.join("image-start.sha256"), &source_hash).unwrap();
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let volume = NtfsVolume::open(Arc::new(Image::new(original)), limits(), &r).unwrap();
    let tree = NtfsTreeSource::inventory_with_policy(
        volume,
        128,
        16,
        index_limits(),
        NtfsTreePolicy::UserNamespace,
        &r,
    )
    .unwrap()
    .with_security_capture(
        NtfsSecureLimits {
            descriptor: NtfsSecurityLimits {
                bytes: 65536,
                aces: 1024,
                work: 100000,
            },
            blocks: 128,
            entries: 4096,
            depth: 16,
            work: 1 << 26,
        },
        &r,
    )
    .unwrap();
    let page = tree.directory_page(&tree.root(), None, 128, &r).unwrap();
    assert!(page.next.is_none());
    assert!(!page.entries.is_empty());
    let mut ids = vec![tree.root()];
    ids.extend(page.entries.iter().map(|e| e.object.clone()));
    for id in &ids {
        let n = u64::from_le_bytes(id.native.as_slice().try_into().unwrap());
        let result = Command::new(&tool)
            .args(["-i", &n.to_string(), "-a", "0x50"])
            .arg(&image)
            .output()
            .unwrap();
        fs::write(out.join(format!("{n}.stdout")), &result.stdout).unwrap();
        fs::write(out.join(format!("{n}.stderr")), &result.stderr).unwrap();
        assert!(result.status.success());
        let baseline = r.memory.used();
        let metadata = tree.metadata(id, &r).unwrap();
        assert_eq!(
            metadata.get().security,
            MetadataField::Known(result.stdout.clone())
        );
        let owner = u32::from_le_bytes(result.stdout[4..8].try_into().unwrap()) as usize;
        if owner != 0 {
            let size = 8 + usize::from(result.stdout[owner + 1]) * 4;
            assert_eq!(
                metadata.get().owner,
                MetadataField::Known(result.stdout[owner..owner + size].to_vec())
            );
        } else {
            assert_eq!(metadata.get().owner, MetadataField::Absent);
        }
        drop(metadata);
        assert_eq!(r.memory.used(), baseline);
    }
    let count = ids.len();
    drop((ids, page, tree));
    assert_eq!(r.memory.used(), 0);
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&image).unwrap())),
        source_hash
    );
    assert_eq!(source_guard(false), bindings);
    fs::write(out.join("source-end.sha256"), &bindings).unwrap();
    assert_eq!(fs::read(&tool).unwrap(), tool_bytes);
    assert_eq!(fs::read(std::env::current_exe().unwrap()).unwrap(), binary);
    fs::write(out.join("receipt.txt"),format!("status=passed\nobjects={count}\nsource_sha256={source_hash}\nprofile=explicit user namespace; native per-record ACL bytes; no complete volume or restore claim\n")).unwrap();
}
