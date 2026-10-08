use partmgr::{
    fs_core::{Budget, Cancellation, NativeName, Resources},
    fs_ext::ExtVolume,
};
use sha2::{Digest, Sha256};
use std::{io, process::Command, sync::Arc};
use virtdisk::ReadAt;
struct Image(Vec<u8>);
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(o).map_err(io::Error::other)?;
        let end = start
            .checked_add(b.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        b.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    }
}
fn w(b: &mut [u8], p: usize, n: u16) {
    b[p..p + 2].copy_from_slice(&n.to_le_bytes())
}
fn d(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes())
}
// Independent handcrafted ext2 layout, not assembled by production code.
fn fixture() -> Vec<u8> {
    let mut b = vec![0; 64 * 1024];
    let s = &mut b[1024..2048];
    d(s, 0, 16);
    d(s, 4, 64);
    d(s, 20, 1);
    d(s, 32, 64);
    d(s, 36, 64);
    d(s, 40, 16);
    w(s, 56, 0xef53);
    w(s, 58, 1);
    d(s, 76, 1);
    w(s, 88, 128);
    d(s, 96, 2);
    d(&mut b, 2048, 3);
    d(&mut b, 2052, 4);
    d(&mut b, 2056, 5);
    b[3072..3080].fill(255);
    b[4096] = 6;
    let root = 5 * 1024 + 128;
    w(&mut b, root, 0x41ed);
    d(&mut b, root + 4, 1024);
    w(&mut b, root + 26, 2);
    d(&mut b, root + 40, 7);
    let file = root + 128;
    w(&mut b, file, 0x81a4);
    d(&mut b, file + 4, 14 * 1024);
    w(&mut b, file + 26, 1);
    d(&mut b, file + 40, 8);
    d(&mut b, file + 88, 9);
    d(&mut b, 9 * 1024, 10);
    b[8 * 1024..9 * 1024].fill(42);
    b[10 * 1024..11 * 1024].fill(99);
    let dir = 7 * 1024;
    d(&mut b, dir, 2);
    w(&mut b, dir + 4, 12);
    b[dir + 6] = 1;
    b[dir + 7] = 2;
    b[dir + 8] = b'.';
    d(&mut b, dir + 12, 2);
    w(&mut b, dir + 16, 12);
    b[dir + 18] = 2;
    b[dir + 19] = 2;
    b[dir + 20..dir + 22].copy_from_slice(b"..");
    d(&mut b, dir + 24, 3);
    w(&mut b, dir + 28, 1000);
    b[dir + 30] = 2;
    b[dir + 31] = 1;
    b[dir + 32..dir + 34].copy_from_slice(&[b'x', 255]);
    b
}
#[test]
fn direct_indirect_sparse_native_names() {
    let r = resources();
    let v = ExtVolume::open(Arc::new(Image(fixture())), &r).unwrap();
    let directory = v.directory(2, 4, 8, &r).unwrap();
    assert_eq!(
        directory.entries()[2].name,
        NativeName::Bytes(vec![b'x', 255])
    );
    let f = v.open_file(3, 20, &r).unwrap();
    let mut bytes = [0; 4];
    f.read_at(0, &mut bytes, &r).unwrap();
    assert_eq!(bytes, [42; 4]);
    f.read_at(1024, &mut bytes, &r).unwrap();
    assert_eq!(bytes, [0; 4]);
    f.read_at(12 * 1024, &mut bytes, &r).unwrap();
    assert_eq!(bytes, [99; 4]);
    f.read_at(13 * 1024, &mut bytes, &r).unwrap();
    assert_eq!(bytes, [0; 4]);
    drop(f);
    drop(directory);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn rejects_feature_cycle_unallocated_and_budget() {
    let r = resources();
    let mut b = fixture();
    d(&mut b, 1120, 0x80);
    assert_eq!(
        ExtVolume::open(Arc::new(Image(b)), &r)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Unsupported
    );
    let mut b = fixture();
    d(&mut b, 9 * 1024, 9);
    let v = ExtVolume::open(Arc::new(Image(b)), &r).unwrap();
    assert!(v.open_file(3, 20, &r).is_err());
    let mut b = fixture();
    b[3072] &= !(1 << 7);
    let v = ExtVolume::open(Arc::new(Image(b)), &r).unwrap();
    assert!(v.open_file(3, 20, &r).is_err());
    let v = ExtVolume::open(Arc::new(Image(fixture())), &r).unwrap();
    assert!(v.open_file(3, 1, &r).is_err());
    r.cancellation.cancel();
    assert!(v.inode(2, &r).is_err());
}
#[test]
fn native_mke2fs_read_only_fixture() {
    for tool in ["mke2fs", "debugfs", "e2fsck"] {
        if Command::new(tool).arg("-V").output().is_err() {
            eprintln!("native ext2 fixture skipped: {tool} unavailable");
            return;
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("ext2.img");
    let f = std::fs::File::create(&path).unwrap();
    f.set_len(8 * 1024 * 1024).unwrap();
    let out = Command::new("mke2fs")
        .args(["-q", "-F", "-t", "ext2", "-O", "none", "-I", "128"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let expected: Vec<u8> = (0..130_123)
        .map(|n| ((n * 37 + n / 31) % 251) as u8)
        .collect();
    let payload = tmp.path().join("payload.bin");
    std::fs::write(&payload, &expected).unwrap();
    let command = format!("write {} /payload.bin", payload.display());
    let out = Command::new("debugfs")
        .args(["-w", "-R", &command])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let unchanged = std::fs::read(&path).unwrap();
    let r = resources();
    let v = ExtVolume::open(Arc::new(Image(std::fs::read(&path).unwrap())), &r).unwrap();
    let dir = v.directory(2, 32, 32, &r).unwrap();
    assert!(
        dir.entries()
            .iter()
            .any(|e| e.name == NativeName::Bytes(b"lost+found".to_vec()))
    );
    let entry = dir
        .entries()
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"payload.bin".to_vec()))
        .unwrap();
    let file = v.open_file(entry.inode, 512, &r).unwrap();
    assert_eq!(file.len(), expected.len() as u64);
    for _ in 0..3 {
        for offset in [0, 1, 12 * 1024 - 7, 12 * 1024, 100_003, expected.len() - 17] {
            let mut bytes = [0; 17];
            assert_eq!(file.read_at(offset as u64, &mut bytes, &r).unwrap(), 17);
            assert_eq!(bytes.as_slice(), &expected[offset..offset + 17]);
        }
    }
    let mut actual = vec![0; expected.len()];
    assert_eq!(file.read_at(0, &mut actual, &r).unwrap(), actual.len());
    assert_eq!(Sha256::digest(&actual), Sha256::digest(&expected));
    let out = Command::new("e2fsck")
        .args(["-fn"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&path).unwrap(), unchanged);
}

#[test]
fn malformed_directory_and_truncated_source_fail() {
    let r = resources();
    let mut b = fixture();
    w(&mut b, 7 * 1024 + 4, 10);
    let v = ExtVolume::open(Arc::new(Image(b)), &r).unwrap();
    assert!(v.directory(2, 4, 8, &r).is_err());
    let mut b = fixture();
    b.truncate(2048);
    assert!(ExtVolume::open(Arc::new(Image(b)), &r).is_err());
    let v = ExtVolume::open(Arc::new(Image(fixture())), &r).unwrap();
    let tiny = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert!(v.open_file(3, 20, &tiny).is_err());
    assert_eq!(tiny.memory.used(), 0);
    assert!(v.directory(2, 4, 2, &r).is_err());
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn common_file_contract_and_source_scoped_identity() {
    use partmgr::fs_core::{FileRead, read_all};
    let r = resources();
    let v = ExtVolume::open(Arc::new(Image(fixture())), &r).unwrap();
    let other = ExtVolume::open(Arc::new(Image(fixture())), &r).unwrap();
    assert_ne!(v.identity(3, &r).unwrap(), other.identity(3, &r).unwrap());
    let file = v.open_file(3, 20, &r).unwrap();
    assert_eq!(FileRead::identity(&file), &v.identity(3, &r).unwrap());
    let content = read_all(&file, 20 * 1024, &r).unwrap();
    assert_eq!(&content.bytes[..4], &[42; 4]);
    assert_eq!(
        FileRead::read_at(&file, u64::MAX, &mut [0; 1], &r).unwrap(),
        0
    );
    let mut extents = 0;
    file.visit_extents(&r, &mut |_| {
        extents += 1;
        Ok(())
    })
    .unwrap();
    assert!(extents >= 3);
}

struct CountedImage {
    bytes: Vec<u8>,
    reads: std::sync::Mutex<Vec<(u64, usize)>>,
    fail_indirect: std::sync::atomic::AtomicBool,
}
impl ReadAt for CountedImage {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.lock().unwrap().push((offset, out.len()));
        if offset == 9 * 1024
            && self
                .fail_indirect
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            out.fill(0xa5);
            return Err(io::Error::other("injected partial indirect metadata read"));
        }
        let at = usize::try_from(offset).map_err(io::Error::other)?;
        out.copy_from_slice(
            self.bytes
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn counted(bytes: Vec<u8>) -> Arc<CountedImage> {
    Arc::new(CountedImage {
        bytes,
        reads: std::sync::Mutex::new(Vec::new()),
        fail_indirect: std::sync::atomic::AtomicBool::new(false),
    })
}
#[test]
fn metadata_index_reads_each_block_once_without_payload_prefetch() {
    use partmgr::fs_core::FileRead;
    let r = resources();
    let mut b = fixture();
    d(&mut b, 5 * 1024 + 256 + 100, 77);
    let source = counted(b);
    let volume = ExtVolume::open(source.clone(), &r).unwrap();
    source.reads.lock().unwrap().clear();
    let file = volume.open_file(3, 20, &r).unwrap();
    let reads = source.reads.lock().unwrap().clone();
    // Descriptor block, inode bitmap/table, allocation bitmap and one indirect
    // block. Allocation checks and both indirect slots reuse these five blocks.
    assert_eq!(reads.len(), 5);
    assert!(reads.iter().all(|(_, n)| *n == 1024));
    assert!(
        !reads
            .iter()
            .any(|(at, _)| *at == 8 * 1024 || *at == 10 * 1024)
    );
    assert_eq!(file.identity().generation, 77);
    let map_charge = r.memory.used();
    assert!(map_charge > 0 && map_charge < 4096);
    source.reads.lock().unwrap().clear();
    let mut bytes = [0; 4];
    for _ in 0..20 {
        file.read_at(12 * 1024, &mut bytes, &r).unwrap();
        assert_eq!(bytes, [99; 4]);
    }
    assert_eq!(
        source.reads.lock().unwrap().as_slice(),
        &[(10 * 1024, 4); 20]
    );
    let second = volume.open_file(3, 20, &r).unwrap();
    assert_eq!(file.identity(), second.identity());
    drop(second);
    assert_eq!(r.memory.used(), map_charge);
    drop(file);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn metadata_cache_failure_cancellation_and_budget_refund() {
    use std::sync::atomic::Ordering;
    let r = resources();
    let source = counted(fixture());
    let volume = ExtVolume::open(source.clone(), &r).unwrap();
    source.fail_indirect.store(true, Ordering::Relaxed);
    assert!(volume.open_file(3, 20, &r).is_err());
    assert_eq!(r.memory.used(), 0);
    // Failed partially overwritten metadata is never published as cached data;
    // a fresh successful construction validates and reads the real pointers.
    source.fail_indirect.store(false, Ordering::Relaxed);
    let file = volume.open_file(3, 20, &r).unwrap();
    let mut b = [0; 4];
    file.read_at(12 * 1024, &mut b, &r).unwrap();
    assert_eq!(b, [99; 4]);
    drop(file);
    assert_eq!(r.memory.used(), 0);
    let tiny = Resources {
        memory: Budget::new(4096),
        cancellation: Cancellation::default(),
    };
    source.reads.lock().unwrap().clear();
    assert!(volume.open_file(3, 20, &tiny).is_err());
    assert_eq!(tiny.memory.used(), 0);
    assert!(source.reads.lock().unwrap().is_empty());
    r.cancellation.cancel();
    assert!(volume.open_file(3, 20, &r).is_err());
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn metadata_cache_preserves_concurrent_uncached_payload_reads() {
    let r = resources();
    let source = counted(fixture());
    let volume = ExtVolume::open(source.clone(), &r).unwrap();
    let file = volume.open_file(3, 20, &r).unwrap();
    source.reads.lock().unwrap().clear();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let file = &file;
            let r = &r;
            scope.spawn(move || {
                let mut b = [0; 4];
                for _ in 0..100 {
                    file.read_at(0, &mut b, r).unwrap();
                    assert_eq!(b, [42; 4]);
                }
            });
        }
    });
    assert_eq!(source.reads.lock().unwrap().len(), 400);
    assert!(
        source
            .reads
            .lock()
            .unwrap()
            .iter()
            .all(|(at, n)| *at == 8 * 1024 && *n == 4)
    );
    drop(file);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn configurable_metadata_cache_work_counts_low_memory_and_refunds() {
    use partmgr::fs_core::FileRead;
    let source = counted(fixture());
    let r = resources();
    let volume = ExtVolume::open(source.clone(), &r).unwrap();
    let mut expected_identity = None;
    let mut expected_hash = None;
    for (cap, expected_reads) in [(64, 5), (0, 18), (1, 14), (4096, 5)] {
        let limits = Resources {
            memory: Budget::new(if cap >= 64 { 8 << 20 } else { 4096 }),
            cancellation: Cancellation::default(),
        };
        source.reads.lock().unwrap().clear();
        let file = volume.open_file_with_cache(3, 20, cap, &limits).unwrap();
        assert_eq!(source.reads.lock().unwrap().len(), expected_reads);
        assert!(
            source
                .reads
                .lock()
                .unwrap()
                .iter()
                .all(|(at, _)| *at < 8 * 1024
                    || *at == 9 * 1024
                    || (cap == 0 && *at >= 9 * 1024 && *at < 10 * 1024))
        );
        let identity = file.identity().clone();
        if let Some(expected) = expected_identity.as_ref() {
            assert_eq!(expected, &identity);
        } else {
            expected_identity = Some(identity);
        }
        // Identical full sparse payload and generation/source identity, despite
        // different cache caps and backend work; only the map remains charged.
        assert!(limits.memory.used() > 0 && limits.memory.used() < 4096);
        let mut bytes = vec![0; file.len() as usize];
        file.read_at(0, &mut bytes, &limits).unwrap();
        let hash = Sha256::digest(&bytes);
        if let Some(expected) = expected_hash.as_ref() {
            assert_eq!(expected, &hash);
        } else {
            expected_hash = Some(hash);
        }
        drop(file);
        assert_eq!(limits.memory.used(), 0);
    }
    source.reads.lock().unwrap().clear();
    assert_eq!(
        volume
            .open_file_with_cache(3, 20, 4097, &r)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(source.reads.lock().unwrap().is_empty());
    assert_eq!(r.memory.used(), 0);
}
