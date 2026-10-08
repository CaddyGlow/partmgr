use partmgr::{
    fs_core::{
        Budget, Cancellation, ErrorKind, MetadataField, NativeName, Resources, StreamKind,
        TreeSource,
    },
    fs_ext::ExtVolume,
    fs_ext_tree::ExtTreeSource,
};

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
    w(&mut b, dir + 28, 16);
    d(&mut b, dir + 40, 3);
    w(&mut b, dir + 44, 984);
    b[dir + 46] = 5;
    b[dir + 47] = 1;
    b[dir + 48..dir + 53].copy_from_slice(b"alias");
    b
}
fn inventory(b: Vec<u8>, r: &Resources) -> partmgr::fs_core::Result<ExtTreeSource> {
    let volume = ExtVolume::open(Arc::new(Image(b)), r).unwrap();
    ExtTreeSource::inventory(volume, 16, 16, 512, 32, r)
}
#[test]
fn native_names_hardlinks_paging_metadata_and_drop() {
    let r = resources();
    let tree = inventory(fixture(), &r).unwrap();
    let root = tree.root();
    let page = tree.directory_page(&root, None, 1, &r).unwrap();
    assert_eq!(page.entries[0].name, NativeName::Bytes(vec![b'x', 255]));
    let second = tree
        .directory_page(&root, page.next.as_deref(), 1, &r)
        .unwrap();
    assert_eq!(second.entries[0].name, NativeName::Bytes(b"alias".to_vec()));
    assert_eq!(page.entries[0].object, second.entries[0].object);
    assert!(second.next.is_none());
    let object = &page.entries[0].object;
    let meta = tree.metadata(object, &r).unwrap();
    assert!(matches!(meta.mode, MetadataField::Known(0x81a4)));
    assert!(matches!(meta.owner, MetadataField::Known(_)));
    assert!(matches!(meta.modified, MetadataField::Opaque { .. }));
    let streams = tree.streams(object, &r).unwrap();
    assert_eq!(streams.len(), 1);
    assert!(tree.streams(&root, &r).unwrap().is_empty());
    let file = tree.open_stream(object, &StreamKind::Data, &r).unwrap();
    let mut bytes = [0; 4];
    file.read_at(0, &mut bytes, &r).unwrap();
    assert_eq!(bytes, [42; 4]);
    assert!(tree.open_stream(&root, &StreamKind::Data, &r).is_err());
    let foreign = inventory(fixture(), &r).unwrap();
    assert_eq!(
        tree.revalidate(&foreign.root(), &r).err().unwrap().kind,
        ErrorKind::StalePlan
    );
    assert!(
        foreign
            .directory_page(&foreign.root(), page.next.as_deref(), 1, &r)
            .is_err()
    );
    drop(foreign);
    drop(file);
    drop(meta);
    drop(streams);
    drop(second);
    drop(page);
    drop(tree);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn topology_alias_limits_and_cancellation() {
    let r = resources();
    let mut b = fixture();
    d(&mut b, 7 * 1024 + 12, 3);
    assert_eq!(inventory(b, &r).err().unwrap().kind, ErrorKind::InvalidData);
    assert_eq!(r.memory.used(), 0);
    let mut b = fixture();
    d(&mut b, 7 * 1024 + 24, 2);
    b[7 * 1024 + 31] = 2;
    assert_eq!(inventory(b, &r).err().unwrap().kind, ErrorKind::InvalidData);
    let mut b = fixture();
    w(&mut b, 5 * 1024 + 256, 0x21ff);
    b[7 * 1024 + 31] = 3;
    b[7 * 1024 + 47] = 3;
    assert_eq!(inventory(b, &r).err().unwrap().kind, ErrorKind::Unsupported);
    let volume = ExtVolume::open(Arc::new(Image(fixture())), &r).unwrap();
    assert_eq!(
        ExtTreeSource::inventory(volume, 1, 16, 32, 32, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
    let tree = inventory(fixture(), &r).unwrap();
    r.cancellation.cancel();
    assert_eq!(
        tree.metadata(&tree.root(), &r).err().unwrap().kind,
        ErrorKind::Cancelled
    );
    drop(tree);
    assert_eq!(r.memory.used(), 0);
}
#[test]
#[ignore = "explicit native e2fsprogs evidence gate; requires PARTMGR_EXT_TREE_EVIDENCE"]
fn native_debugfs_hardlink_inventory() {
    use sha2::{Digest, Sha256};
    let destination = std::path::PathBuf::from(
        std::env::var("PARTMGR_EXT_TREE_EVIDENCE")
            .expect("native gate requires evidence destination"),
    );
    assert!(destination.is_absolute());
    let directory = destination.join(format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let mut receipt = String::new();
    receipt.push_str("source_specs=https://raw.githubusercontent.com/torvalds/linux/master/fs/ext2/inode.c https://raw.githubusercontent.com/torvalds/linux/master/fs/ext2/ext2.h\n");
    for tool in ["mke2fs", "debugfs", "e2fsck"] {
        let executable = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
            .expect("native executable must resolve");
        receipt.push_str(&format!(
            "tool {} sha256 {:x} argv=-V\n",
            executable.display(),
            Sha256::digest(std::fs::read(&executable).unwrap())
        ));
        let out = Command::new(tool)
            .arg("-V")
            .output()
            .expect("enabled native gate requires all e2fsprogs tools");
        std::fs::write(
            directory.join(format!("{tool}-version.txt")),
            [&out.stdout[..], &out.stderr[..]].concat(),
        )
        .unwrap();
    }
    let tmp = directory;
    let path = tmp.join("ext2.img");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(8 * 1024 * 1024)
        .unwrap();
    receipt.push_str(&format!(
        "argv mke2fs -q -F -t ext2 -O none -I 128 {:?}\n",
        path
    ));
    let out = Command::new("mke2fs")
        .args(["-q", "-F", "-t", "ext2", "-O", "none", "-I", "128"])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::write(
        tmp.join("mke2fs-output.txt"),
        [&out.stdout[..], &out.stderr[..]].concat(),
    )
    .unwrap();
    assert!(out.status.success());
    let bytes: Vec<u8> = (0..100_003)
        .map(|i| ((i * 43 + i / 17) % 251) as u8)
        .collect();
    let payload = tmp.join("data");
    std::fs::write(&payload, &bytes).unwrap();
    let commands = tmp.join("commands");
    let long_target = "../".to_owned() + &"native-target-".repeat(8);
    std::fs::write(
        &commands,
        format!(
            "write {} /payload\nlink /payload /alias\nset_inode_field /payload links_count 2\nset_inode_field /payload uid 70001\nset_inode_field /payload gid 80002\nset_inode_field /payload atime @1700000001\nset_inode_field /payload mtime @1700000002\nset_inode_field /payload ctime @1700000003\nsymlink /short ../payload\nsymlink /long {}\n",
            payload.display(), long_target
        ),
    )
    .unwrap();
    receipt.push_str(&format!("argv debugfs -w -f {:?} {:?}\n", commands, path));
    let out = Command::new("debugfs")
        .args(["-w", "-f"])
        .arg(&commands)
        .arg(&path)
        .output()
        .unwrap();
    std::fs::write(
        tmp.join("debugfs-output.txt"),
        [&out.stdout[..], &out.stderr[..]].concat(),
    )
    .unwrap();
    assert!(out.status.success());
    for name in ["payload", "short", "long"] {
        let request = format!("stat /{name}");
        receipt.push_str(&format!("argv debugfs -R {:?} {:?}\n", request, path));
        let out = Command::new("debugfs")
            .args(["-R", &request])
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success());
        std::fs::write(
            tmp.join(format!("stat-{name}.txt")),
            [&out.stdout[..], &out.stderr[..]].concat(),
        )
        .unwrap();
        if name == "short" {
            assert!(String::from_utf8_lossy(&out.stdout).contains("Fast link dest:"));
        }
        if name == "long" {
            assert!(String::from_utf8_lossy(&out.stdout).contains("Blockcount: 2"));
        }
        if name == "payload" {
            let native = String::from_utf8_lossy(&out.stdout);
            assert!(
                native.contains("70001") && native.contains("80002"),
                "{native}"
            );
            for encoded in ["0x6553f101", "0x6553f102", "0x6553f103"] {
                assert!(native.contains(encoded), "{native}");
            }
        }
    }
    let native_target = tmp.join("long-target.bin");
    let request = format!("dump /long {}", native_target.display());
    receipt.push_str(&format!("argv debugfs -R {:?} {:?}\n", request, path));
    let out = Command::new("debugfs")
        .args(["-R", &request])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::write(
        tmp.join("debugfs-dump-output.txt"),
        [&out.stdout[..], &out.stderr[..]].concat(),
    )
    .unwrap();
    assert!(out.status.success());
    assert_eq!(
        std::fs::read(native_target).unwrap(),
        long_target.as_bytes()
    );
    let unchanged = std::fs::read(&path).unwrap();
    let r = resources();
    let tree = inventory(unchanged.clone(), &r).unwrap();
    let page = tree.directory_page(&tree.root(), None, 32, &r).unwrap();
    let original = page
        .entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"payload".to_vec()))
        .unwrap();
    let alias = page
        .entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"alias".to_vec()))
        .unwrap();
    assert_eq!(original.object, alias.object);
    let meta = tree.metadata(&original.object, &r).unwrap();
    let mut ownership = 70001u32.to_le_bytes().to_vec();
    ownership.extend_from_slice(&80002u32.to_le_bytes());
    assert_eq!(meta.owner, MetadataField::Known(ownership));
    assert!(
        matches!(meta.modified, MetadataField::Opaque { ref bytes, .. } if bytes == &1700000002u32.to_le_bytes())
    );
    assert!(
        matches!(meta.accessed, MetadataField::Opaque { ref bytes, .. } if bytes == &1700000001u32.to_le_bytes())
    );
    for (name, target) in [("short", "../payload"), ("long", long_target.as_str())] {
        let entry = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(name.as_bytes().to_vec()))
            .unwrap();
        assert_eq!(entry.kind, partmgr::fs_core::ObjectKind::Symlink);
        let symlink = tree.metadata(&entry.object, &r).unwrap();
        assert_eq!(
            symlink.symlink_target,
            MetadataField::Known(NativeName::Bytes(target.as_bytes().to_vec()))
        );
        assert!(tree.streams(&entry.object, &r).unwrap().is_empty());
        assert_eq!(
            tree.open_stream(&entry.object, &StreamKind::Data, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::InvalidOperation
        );
    }
    drop(meta);

    let file = tree
        .open_stream(&alias.object, &StreamKind::Data, &r)
        .unwrap();
    let actual = partmgr::fs_core::read_all(&*file, 200_000, &r).unwrap();
    assert_eq!(actual.bytes, bytes);
    receipt.push_str(&format!("argv e2fsck -fn {:?}\n", path));
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
    std::fs::write(
        tmp.join("e2fsck-fn.txt"),
        [&out.stdout[..], &out.stderr[..]].concat(),
    )
    .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), unchanged);
    receipt.push_str("result=passed\ncommands: mke2fs -q -F -t ext2 -O none -I 128 ext2.img; debugfs -w -f commands ext2.img; debugfs -R stat /{payload,short,long} ext2.img; e2fsck -fn ext2.img\n");
    for file in [
        path.clone(),
        commands.clone(),
        payload.clone(),
        std::path::PathBuf::from("src/fs_ext.rs"),
        std::path::PathBuf::from("src/fs_ext_tree.rs"),
        std::path::PathBuf::from("tests/fs_ext_tree.rs"),
        std::path::PathBuf::from("Cargo.lock"),
    ] {
        receipt.push_str(&format!(
            "sha256 {} {:x}\n",
            file.display(),
            Sha256::digest(std::fs::read(&file).unwrap())
        ));
    }
    for item in std::fs::read_dir(&tmp).unwrap() {
        let file = item.unwrap().path();
        receipt.push_str(&format!(
            "artifact {} sha256 {:x}\n",
            file.display(),
            Sha256::digest(std::fs::read(&file).unwrap())
        ));
        std::fs::File::open(&file).unwrap().sync_all().unwrap();
    }
    let receipt_path = tmp.join("receipt.txt");
    std::fs::write(&receipt_path, receipt).unwrap();
    std::fs::File::open(receipt_path)
        .unwrap()
        .sync_all()
        .unwrap();
    std::fs::File::open(&tmp).unwrap().sync_all().unwrap();
    eprintln!("native ext tree evidence: {}", tmp.display());
    drop(actual);
    drop(file);
    drop(page);
    drop(tree);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn inline_and_block_symlinks_are_unfollowed_native_metadata() {
    for (target, blocks) in [(b"../\xfftarget".as_slice(), 0), (&[b'x'; 100][..], 2)] {
        let r = resources();
        let mut bytes = fixture();
        let at = 5 * 1024 + 256;
        w(&mut bytes, at, 0xa1ff);
        d(&mut bytes, at + 4, target.len() as u32);
        d(&mut bytes, at + 28, blocks);
        bytes[at + 40..at + 100].fill(0);
        if blocks == 0 {
            bytes[at + 40..at + 40 + target.len()].copy_from_slice(target);
        } else {
            d(&mut bytes, at + 40, 8);
            bytes[8 * 1024..8 * 1024 + target.len()].copy_from_slice(target);
        }
        bytes[7 * 1024 + 31] = 7;
        bytes[7 * 1024 + 47] = 7;
        w(&mut bytes, at + 2, 0x1234);
        w(&mut bytes, at + 120, 0xabcd);
        w(&mut bytes, at + 24, 0x5678);
        w(&mut bytes, at + 122, 0xef01);
        d(&mut bytes, at + 8, 0xffff_ffff);
        d(&mut bytes, at + 12, 7);
        d(&mut bytes, at + 16, 42);
        let tree = inventory(bytes, &r).unwrap();
        let page = tree.directory_page(&tree.root(), None, 2, &r).unwrap();
        assert_eq!(page.entries[0].object, page.entries[1].object);
        assert_eq!(page.entries[0].kind, partmgr::fs_core::ObjectKind::Symlink);
        let meta = tree.metadata(&page.entries[0].object, &r).unwrap();
        assert_eq!(
            meta.symlink_target,
            MetadataField::Known(NativeName::Bytes(target.to_vec()))
        );
        assert_eq!(
            meta.owner,
            MetadataField::Known(
                [0xabcd1234u32.to_le_bytes(), 0xef015678u32.to_le_bytes()].concat()
            )
        );
        assert!(
            matches!(meta.accessed, MetadataField::Opaque { ref bytes, .. } if bytes == &[255; 4])
        );
        assert_eq!(meta.attributes.len(), 2);
        assert!(
            tree.streams(&page.entries[0].object, &r)
                .unwrap()
                .is_empty()
        );
        drop((meta, page, tree));
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn malformed_symlink_and_all_special_kinds_refund() {
    for mode in [0x1000, 0x2000, 0x6000, 0xc000] {
        let r = resources();
        let mut b = fixture();
        let at = 5 * 1024 + 256;
        w(&mut b, at, mode);
        for offset in [7, 19, 31, 47] {
            b[7 * 1024 + offset] = 0;
        }
        b[1024 + 96] = 0; // Legacy directories carry no native file-type discriminator.
        assert_eq!(inventory(b, &r).err().unwrap().kind, ErrorKind::Unsupported);
        assert_eq!(r.memory.used(), 0);
    }
    for length in [0, 3, 60] {
        let r = resources();
        let mut b = fixture();
        let at = 5 * 1024 + 256;
        w(&mut b, at, 0xa1ff);
        d(&mut b, at + 4, length);
        b[at + 40..at + 100].fill(0);
        for offset in [7, 19, 31, 47] {
            b[7 * 1024 + offset] = 0;
        }
        b[1024 + 96] = 0;
        assert_eq!(inventory(b, &r).err().unwrap().kind, ErrorKind::InvalidData);
        assert_eq!(r.memory.used(), 0);
    }
}
