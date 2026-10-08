#[path = "fixtures/ext2_clean.rs"]
mod independent;
use partmgr::{
    fs_core::{Budget, Cancellation, NativeName, Resources},
    fs_ext::ExtVolume,
    fs_ext_audit::{self, ExtAuditLimits},
};
use std::{io, sync::Arc};
use virtdisk::ReadAt;
struct Image(Vec<u8>);
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(at).map_err(io::Error::other)?;
        let end = at
            .checked_add(b.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        b.copy_from_slice(self.0.get(at..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
fn w(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes())
}
fn d(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes())
}
const INODE: usize = 6400;
fn fixture(indexed: bool) -> Vec<u8> {
    let mut b = independent::fixture();
    d(&mut b, 1120, 0x42);
    d(&mut b, INODE + 32, 0x80000);
    d(&mut b, INODE + 4, 4 * 1024);
    b[INODE + 40..INODE + 100].fill(0);
    let root = INODE + 40;
    w(&mut b, root, 0xf30a);
    w(&mut b, root + 2, if indexed { 1 } else { 2 });
    w(&mut b, root + 4, 4);
    w(&mut b, root + 6, u16::from(indexed));
    let leaf = if indexed { 10 * 1024 } else { root };
    if indexed {
        d(&mut b, root + 12, 0);
        d(&mut b, root + 16, 10);
        w(&mut b, leaf, 0xf30a);
        w(&mut b, leaf + 2, 2);
        w(&mut b, leaf + 4, 84);
    }
    d(&mut b, leaf + 12, 0);
    w(&mut b, leaf + 16, 1);
    d(&mut b, leaf + 20, 8);
    d(&mut b, leaf + 24, 2);
    w(&mut b, leaf + 28, 32770);
    d(&mut b, leaf + 32, 9);
    // One initialized block, a hole, two poisoned but logically-zero unwritten blocks.
    b[9 * 1024..10 * 1024].fill(0xbb);
    if !indexed {
        b[10 * 1024..11 * 1024].fill(0xcc)
    }
    // Indexed fixture moves unwritten allocation away from the extent metadata block.
    if indexed {
        d(&mut b, leaf + 32, 11);
        b[11 * 1024..13 * 1024].fill(0xdd);
    }
    let allocated = if indexed { 4u16 } else { 3 };
    for block in if indexed {
        vec![10u32, 11, 12]
    } else {
        vec![9, 10]
    } {
        let bit = block - 1;
        b[3072 + bit as usize / 8] |= 1 << (bit % 8);
    }
    d(&mut b, 1036, u32::from(55 - allocated + 1));
    w(&mut b, 2060, 55 - allocated + 1);
    d(&mut b, INODE + 28, u32::from(allocated) * 2);
    b
}
fn r() -> Resources {
    Resources {
        memory: Budget::new(2 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ExtAuditLimits {
    ExtAuditLimits {
        blocks: 64,
        inodes: 16,
        work: 65536,
        directory_blocks: 4,
        directory_entries: 32,
        findings: 32,
    }
}
#[test]
fn initialized_sparse_unwritten_indexed_and_complete_allocation_audit() {
    for indexed in [false, true] {
        let r = r();
        let v = ExtVolume::open(Arc::new(Image(fixture(indexed))), &r).unwrap();
        assert!(v.geometry().uses_extents());
        let dir = v.directory(2, 4, 32, &r).unwrap();
        assert!(
            dir.entries()
                .iter()
                .any(|e| e.name == NativeName::Bytes(b"alias".to_vec()))
        );
        let file = v.open_file(11, 8, &r).unwrap();
        let mut out = [0; 4096];
        file.read_at(0, &mut out, &r).unwrap();
        assert_eq!(&out[..1024], &[73; 1024]);
        assert_eq!(&out[1024..], &[0; 3072]);
        let audit = fs_ext_audit::audit(&v, limits(), &r).unwrap();
        assert!(audit.is_clean(), "{:?}", audit.findings());
        assert_eq!(audit.owned_blocks(), if indexed { 5 } else { 4 });
        drop((file, dir, audit, v));
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn malformed_extent_depth_keys_aliases_allocation_and_budget_refund() {
    for (at, value) in [
        (INODE + 40, 0u32),
        (INODE + 40 + 6, 6),
        (INODE + 40 + 12, 2),
        (INODE + 40 + 28, 0),
        (INODE + 40 + 32, 8),
    ] {
        let r = r();
        let mut b = fixture(false);
        if at == INODE + 40 + 6 || at == INODE + 40 + 28 {
            w(&mut b, at, value as u16)
        } else {
            d(&mut b, at, value)
        }
        let v = ExtVolume::open(Arc::new(Image(b)), &r).unwrap();
        assert!(v.open_file(11, 8, &r).is_err());
        drop(v);
        assert_eq!(r.memory.used(), 0);
    }
    let r = r();
    let v = ExtVolume::open(Arc::new(Image(fixture(true))), &r).unwrap();
    assert!(v.open_file(11, 2, &r).is_err());
    r.cancellation.cancel();
    assert!(v.open_file(11, 8, &r).is_err());
    drop(v);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn extent_profile_owned_editor_rejects_before_any_write() {
    use partmgr::{
        fs_ext_edit::{ExtEditBinding, ExtEditLimits, ExtEditRegion, ExtEditor},
        fs_undo::UndoLimits,
        storage::Storage,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Owned {
        bytes: Vec<u8>,
        writes: Arc<AtomicUsize>,
    }
    impl Storage for Owned {
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            out.copy_from_slice(
                self.bytes
                    .get(at as usize..at as usize + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
        fn write_at(&mut self, _: u64, b: &[u8]) -> io::Result<usize> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }
    for image in [fixture(false), extended_inode_fixture()] {
        let r = r();
        let writes = Arc::new(AtomicUsize::new(0));
        let result = ExtEditor::open(
            Owned {
                bytes: image,
                writes: writes.clone(),
            },
            Owned {
                bytes: vec![0; 32768],
                writes: writes.clone(),
            },
            ExtEditRegion {
                offset: 0,
                length: 65536,
            },
            ExtEditBinding {
                volume: [4; 32],
                generation: 0,
            },
            ExtEditLimits {
                audit: limits(),
                file_blocks: 64,
                directory_entries: 32,
                affected_bytes: 4096,
                work: 65536,
                undo: UndoLimits {
                    patches: 32,
                    body_bytes: 16384,
                },
            },
            &r,
        );
        assert_eq!(
            result.err().unwrap().kind,
            partmgr::fs_core::ErrorKind::Unsupported
        );
        assert_eq!(writes.load(Ordering::Relaxed), 0);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn preallocation_after_eof_is_owned_and_never_reads_poison() {
    let r = r();
    let mut b = fixture(false);
    d(&mut b, INODE + 4, 2048);
    let v = ExtVolume::open(Arc::new(Image(b)), &r).unwrap();
    let f = v.open_file(11, 8, &r).unwrap();
    let mut bytes = [0x55; 2048];
    assert_eq!(f.read_at(0, &mut bytes, &r).unwrap(), 2048);
    assert_eq!(&bytes[..1024], &[73; 1024]);
    assert_eq!(&bytes[1024..], &[0; 1024]);
    assert_eq!(f.read_at(2048, &mut [0x55; 1], &r).unwrap(), 0);
    let a = fs_ext_audit::audit(&v, limits(), &r).unwrap();
    assert!(a.is_clean(), "{:?}", a.findings());
    assert_eq!(a.owned_blocks(), 4);
    drop((f, a, v));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn index_cycles_bounds_flag_mismatch_and_allocation_gates_refund() {
    for mutation in 0..5 {
        let r = r();
        let mut b = fixture(true);
        match mutation {
            0 => {
                w(&mut b, 10 * 1024 + 2, 1);
                w(&mut b, 10 * 1024 + 6, 1);
                d(&mut b, 10 * 1024 + 16, 10);
            }
            1 => w(&mut b, INODE + 44, 5),
            2 => w(&mut b, 10 * 1024 + 6, 2),
            3 => b[3073] &= !(1 << 1),
            _ => d(&mut b, 1120, 2),
        }
        let v = ExtVolume::open(Arc::new(Image(b)), &r).unwrap();
        assert!(v.open_file(11, 8, &r).is_err(), "mutation{mutation}");
        drop(v);
        assert_eq!(r.memory.used(), 0);
    }
}

fn extended_inode_fixture() -> Vec<u8> {
    let mut image = independent::fixture();
    let old_table = image[5 * 1024..7 * 1024].to_vec();
    image[5 * 1024..7 * 1024].fill(0);
    image[9 * 1024..13 * 1024].fill(0);
    for index in 0..16 {
        image[9 * 1024 + index * 256..9 * 1024 + index * 256 + 128]
            .copy_from_slice(&old_table[index * 128..(index + 1) * 128]);
    }
    w(&mut image, 1112, 256);
    d(&mut image, 1124, 0x40);
    d(&mut image, 2056, 9);
    d(&mut image, 1036, 53);
    w(&mut image, 2060, 53);
    image[3072..4080].fill(0);
    for block in (1..=4).chain(7..=12) {
        image[3072 + (block - 1) / 8] |= 1 << ((block - 1) % 8);
    }
    image[3079] |= 128;
    image[3080..4096].fill(255);
    for index in [1, 10] {
        let at = 9 * 1024 + index * 256;
        w(&mut image, at + 128, 32);
        d(&mut image, at + 132, 493_827_156); // ctime: native nanoseconds 123456789.
        d(&mut image, at + 136, 493_827_159); // two epoch bits are preserved.
        d(&mut image, at + 140, 8);
        d(&mut image, at + 144, 0x8000_0001); // native seconds, no guessed epoch.
        d(&mut image, at + 148, 493_827_158);
    }
    image
}

#[test]
fn extended_linux_inode_stride_native_time_metadata_complete_audit_and_refunds() {
    use partmgr::{
        fs_core::{MetadataField, TreeSource},
        fs_ext_tree::ExtTreeSource,
    };
    let resources = r();
    let volume = ExtVolume::open(Arc::new(Image(extended_inode_fixture())), &resources).unwrap();
    assert!(!volume.geometry().is_classic());
    let inode = volume.inode(11, &resources).unwrap();
    assert_eq!(inode.raw_extended_metadata().len(), 32);
    let id = volume.identity(11, &resources).unwrap();
    let file = volume.open_file(11, 4, &resources).unwrap();
    let mut bytes = [0; 32];
    assert_eq!(file.read_at(3, &mut bytes, &resources).unwrap(), 32);
    assert_eq!(bytes, [73; 32]);
    let audit = fs_ext_audit::audit(&volume, limits(), &resources).unwrap();
    assert!(audit.is_clean(), "{:?}", audit.findings());
    assert_eq!(audit.owned_blocks(), 2);
    let tree = ExtTreeSource::inventory(volume, 16, 16, 32, 32, &resources).unwrap();
    let metadata = tree.metadata(&id, &resources).unwrap();
    match &metadata.created {
        MetadataField::Opaque { bytes, .. } => {
            assert_eq!(bytes, &inode.raw_extended_metadata()[16..24])
        }
        other => panic!("{other:?}"),
    }
    match &metadata.modified {
        MetadataField::Opaque { bytes, .. } => assert_eq!(bytes.len(), 8),
        other => panic!("{other:?}"),
    }
    drop((metadata, tree, file, audit));
    assert_eq!(resources.memory.used(), 0);
}

#[test]
fn extended_inode_malformed_size_nanoseconds_and_inline_xattrs_fail_closed() {
    for (offset, value, short) in [
        (128, 129, true),
        (128, 30, true),
        (132, 4_000_000_000, false),
        (160, 0xea02_0000, false),
    ] {
        let resources = r();
        let mut image = extended_inode_fixture();
        let at = 9 * 1024 + 10 * 256 + offset;
        if short {
            w(&mut image, at, value as u16)
        } else {
            d(&mut image, at, value)
        }
        let volume = ExtVolume::open(Arc::new(Image(image)), &resources).unwrap();
        assert!(volume.inode(11, &resources).is_err());
        assert!(fs_ext_audit::audit(&volume, limits(), &resources).is_err());
        drop(volume);
        assert_eq!(resources.memory.used(), 0);
    }
}
