use partmgr::{fs_core::*, fs_fat::FatVolume, fs_fat_tree::FatTreeSource};
use std::{io, sync::Arc};
use virtdisk::ReadAt;
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
fn slot(image: &mut [u8], offset: usize, name: &[u8; 11], attr: u8, cluster: u16, len: u32) {
    image[offset..offset + 11].copy_from_slice(name);
    image[offset + 11] = attr;
    image[offset + 26..offset + 28].copy_from_slice(&cluster.to_le_bytes());
    image[offset + 28..offset + 32].copy_from_slice(&len.to_le_bytes());
}
fn volume(cycle: bool) -> FatVolume {
    let mut image = vec![0; 512 * 128];
    image[11..13].copy_from_slice(&512u16.to_le_bytes());
    image[13] = 1;
    image[14..16].copy_from_slice(&1u16.to_le_bytes());
    image[16] = 1;
    image[17..19].copy_from_slice(&16u16.to_le_bytes());
    image[19..21].copy_from_slice(&128u16.to_le_bytes());
    image[21] = 0xf8;
    image[22..24].copy_from_slice(&1u16.to_le_bytes());
    image[510..512].copy_from_slice(&[0x55, 0xaa]);
    image[512..521].copy_from_slice(&[0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0]);
    slot(&mut image, 1024, b"PAYLOAD BIN", 0x20, 2, 4);
    slot(&mut image, 1056, b"SUBDIR     ", 0x10, 3, 0);
    slot(&mut image, 2048, b".          ", 0x10, 3, 0);
    slot(&mut image, 2080, b"..         ", 0x10, 0, 0);
    if cycle {
        slot(&mut image, 2112, b"RECURSE    ", 0x10, 3, 0);
    } else {
        slot(&mut image, 2112, b"INNER   BIN", 0x20, 4, 5);
    }
    image[1536..1540].copy_from_slice(b"data");
    image[2560..2565].copy_from_slice(b"inner");
    FatVolume::open(Arc::new(Bytes(image))).unwrap()
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    }
}

#[test]
fn bounded_inventory_pages_nested_names_metadata_and_deferred_streams() {
    let resources = resources();
    let tree = FatTreeSource::inventory(volume(false), 4, 8, 16, &resources).unwrap();
    let root = tree.root();
    let page = tree.directory_page(&root, None, 1, &resources).unwrap();
    assert_eq!(
        page.entries[0].name,
        NativeName::Bytes(b"PAYLOAD BIN".to_vec())
    );
    let payload = page.entries[0].object.clone();
    let next = page.next.as_ref().unwrap();
    let last = tree
        .directory_page(&root, Some(next), 1, &resources)
        .unwrap();
    assert_eq!(last.entries[0].kind, ObjectKind::Directory);
    assert!(last.next.is_none());
    let subdir = last.entries[0].object.clone();
    assert!(
        tree.directory_page(&subdir, Some(next), 1, &resources)
            .is_err()
    );
    let nested = tree.directory_page(&subdir, None, 10, &resources).unwrap();
    assert_eq!(
        nested.entries[0].name,
        NativeName::Bytes(b"INNER   BIN".to_vec())
    );
    let metadata = tree.metadata(&payload, &resources).unwrap();
    assert!(matches!(
        metadata.get().created,
        MetadataField::Opaque { .. }
    ));
    assert!(matches!(metadata.get().owner, MetadataField::Absent));
    assert_eq!(
        tree.streams(&payload, &resources).unwrap().get()[0].length,
        4
    );
    assert!(tree.streams(&subdir, &resources).unwrap().get().is_empty());
    assert!(
        tree.open_stream(&payload, &StreamKind::ResourceFork, &resources)
            .is_err()
    );
    assert!(
        tree.open_stream(&subdir, &StreamKind::Data, &resources)
            .is_err()
    );
    let file = tree
        .open_stream(&payload, &StreamKind::Data, &resources)
        .unwrap();
    assert_eq!(file.identity(), &payload);
    drop(metadata);
    drop(nested);
    drop(last);
    drop(page);
    drop(tree);
    assert_eq!(
        read_all(file.as_ref(), 4, &resources)
            .unwrap()
            .get()
            .as_slice(),
        b"data"
    );
    drop(file);
    assert_eq!(resources.memory.used(), 0);
}

#[test]
fn cycles_limits_foreign_ids_and_cancellation_fail_with_released_budgets() {
    let resources = resources();
    assert!(FatTreeSource::inventory(volume(true), 5, 8, 16, &resources).is_err());
    assert_eq!(resources.memory.used(), 0);
    assert!(FatTreeSource::inventory(volume(false), 3, 8, 16, &resources).is_err());
    assert_eq!(resources.memory.used(), 0);
    let tree = FatTreeSource::inventory(volume(false), 4, 8, 16, &resources).unwrap();
    let mut foreign = tree.root();
    foreign.source += 1;
    assert_eq!(
        tree.metadata(&foreign, &resources).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    resources.cancellation.cancel();
    assert_eq!(
        tree.streams(&tree.root(), &resources).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    drop(tree);
    assert_eq!(resources.memory.used(), 0);
}
