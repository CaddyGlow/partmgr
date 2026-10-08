//! Independently authored e2fsprogs extent/journal fixtures; never production builder seeds.
use partmgr::{
    fs_core::{Budget, Cancellation, FileRead, Resources},
    fs_ext::ExtVolume,
    fs_ext_audit::{self, ExtAuditLimits},
};
use sha2::{Digest, Sha256};
use std::{fs, io, path::PathBuf, process::Command, sync::Arc};
use virtdisk::ReadAt;
struct Image(Vec<u8>);
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(b.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        b.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
#[test]
#[ignore = "explicit ext3/ext4 native gate requires fresh PARTMGR_EXT_PROFILES_EVIDENCE and mke2fs/debugfs/e2fsck"]
fn native_ext3_ext4_extent_and_inactive_journal_profiles() {
    let out = PathBuf::from(
        std::env::var_os("PARTMGR_EXT_PROFILES_EVIDENCE")
            .expect("enabled gate requires evidence destination"),
    );
    assert!(out.is_absolute());
    fs::create_dir(&out).expect("fresh evidence destination required");
    let sources = [
        "src/fs_ext.rs",
        "src/fs_ext_extent.rs",
        "src/fs_ext_journal.rs",
        "src/fs_ext_checksum.rs",
        "src/fs_ext_tree.rs",
        "src/fs_ext_audit.rs",
        "src/fs_core.rs",
        "src/fs_file.rs",
        "tests/fs_ext_profiles_native.rs",
        "tests/fs_ext_extent.rs",
        "tests/fs_ext_journal.rs",
        "Cargo.lock",
    ];
    let mut receipt = String::from(
        "profile=immutable clean 128/256-byte Linux ext3/ext4 without metadata checksums,64bit,flex_bg or directory indexes\nsource_capture=gate-start\n",
    );
    for source in sources {
        let bytes = fs::read(source).unwrap();
        let snapshot = out.join("sources").join(source);
        fs::create_dir_all(snapshot.parent().unwrap()).unwrap();
        fs::write(&snapshot, &bytes).unwrap();
        fs::File::open(&snapshot).unwrap().sync_all().unwrap();
        receipt.push_str(&format!(
            "source={source} sha256={:x}\n",
            Sha256::digest(bytes)
        ));
    }
    let binary = fs::read(std::env::current_exe().unwrap()).unwrap();
    fs::write(out.join("gate-binary"), &binary).unwrap();
    fs::set_permissions(
        out.join("gate-binary"),
        fs::metadata(std::env::current_exe().unwrap())
            .unwrap()
            .permissions(),
    )
    .unwrap();
    receipt.push_str(&format!("binary_sha256={:x}\n", Sha256::digest(binary)));
    let mut tools = std::collections::BTreeMap::new();
    for tool in ["mke2fs", "debugfs", "e2fsck"] {
        let path = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
            .expect("enabled native gate requires all tools");
        receipt.push_str(&format!(
            "tool={tool} path={} sha256={:x}\n",
            path.display(),
            Sha256::digest(fs::read(&path).unwrap())
        ));
        tools.insert(tool, path);
    }
    let mut number = 0;
    let run = |tool: &str, args: Vec<String>, receipt: &mut String, number: &mut usize| {
        let result = Command::new(&tools[tool]).args(&args).output().unwrap();
        let prefix = format!("command-{:04}-{tool}", *number);
        *number += 1;
        fs::write(out.join(format!("{prefix}.stdout")), &result.stdout).unwrap();
        fs::write(out.join(format!("{prefix}.stderr")), &result.stderr).unwrap();
        receipt.push_str(&format!("command={} {args:?} status={} stdout={prefix}.stdout sha256={:x} stderr={prefix}.stderr sha256={:x}\n",tools[tool].display(),result.status,Sha256::digest(&result.stdout),Sha256::digest(&result.stderr)));
        fs::write(out.join("receipt.txt"), &*receipt).unwrap();
        assert!(
            result.status.success(),
            "{tool}: {} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        result.stdout
    };
    for tool in ["mke2fs", "debugfs", "e2fsck"] {
        run(tool, vec!["-V".into()], &mut receipt, &mut number);
    }
    let payload: Vec<u8> = (0..131089)
        .map(|i| ((i * 37 + i / 19 + 11) % 251) as u8)
        .collect();
    let host = out.join("payload.bin");
    fs::write(&host, &payload).unwrap();
    let empty = out.join("empty.bin");
    fs::write(&empty, []).unwrap();
    receipt.push_str(&format!(
        "source_payload_sha256={:x}\n",
        Sha256::digest(&payload)
    ));
    let limits = ExtAuditLimits {
        blocks: 16384,
        inodes: 8192,
        work: 8_000_000,
        directory_blocks: 128,
        directory_entries: 2048,
        findings: 64,
    };
    for (family, features, journal) in [
        ("ext3", "none,has_journal,filetype,sparse_super", true),
        ("ext4", "none,extent,filetype,sparse_super", false),
        (
            "ext4",
            "none,has_journal,extent,filetype,sparse_super",
            true,
        ),
    ] {
        for block in [1024, 2048, 4096] {
            for inode_bytes in [128, 256] {
                let stem = format!("{family}-journal{journal}-b{block}-i{inode_bytes}");
                let image = out.join(format!("{stem}.img"));
                fs::File::create(&image).unwrap().set_len(16 << 20).unwrap();
                run(
                    "mke2fs",
                    vec![
                        "-q".into(),
                        "-F".into(),
                        "-t".into(),
                        family.into(),
                        "-b".into(),
                        block.to_string(),
                        "-I".into(),
                        inode_bytes.to_string(),
                        "-O".into(),
                        features.into(),
                        image.display().to_string(),
                    ],
                    &mut receipt,
                    &mut number,
                );
                run(
                    "debugfs",
                    vec![
                        "-w".into(),
                        "-R".into(),
                        format!("write {} /payload", host.display()),
                        image.display().to_string(),
                    ],
                    &mut receipt,
                    &mut number,
                );
                if inode_bytes == 256 {
                    for command in [
                        "set_inode_field /payload mtime 0x80000001",
                        "set_inode_field /payload mtime_extra 493827159",
                        "set_inode_field /payload crtime 0x80000001",
                        "set_inode_field /payload crtime_extra 493827158",
                    ] {
                        run(
                            "debugfs",
                            vec![
                                "-w".into(),
                                "-R".into(),
                                command.into(),
                                image.display().to_string(),
                            ],
                            &mut receipt,
                            &mut number,
                        );
                    }
                    let stat = run(
                        "debugfs",
                        vec![
                            "-R".into(),
                            "stat /payload".into(),
                            image.display().to_string(),
                        ],
                        &mut receipt,
                        &mut number,
                    );
                    let stat = std::str::from_utf8(&stat).unwrap();
                    assert!(stat.contains("80000001:1d6f3457"), "{stat}");
                    assert!(stat.contains("80000001:1d6f3456"), "{stat}");
                }
                if family == "ext4" {
                    for cmd in [
                        "fallocate /payload 200 202".into(),
                        format!("write {} /indexed", empty.display()),
                        format!("set_inode_field /indexed size {}", 23 * block),
                    ] {
                        run(
                            "debugfs",
                            vec!["-w".into(), "-R".into(), cmd, image.display().to_string()],
                            &mut receipt,
                            &mut number,
                        );
                    }
                    for logical in (0..23).step_by(2) {
                        run(
                            "debugfs",
                            vec![
                                "-w".into(),
                                "-R".into(),
                                format!("fallocate /indexed {logical} {logical}"),
                                image.display().to_string(),
                            ],
                            &mut receipt,
                            &mut number,
                        );
                    }
                }
                run(
                    "e2fsck",
                    vec!["-fn".into(), image.display().to_string()],
                    &mut receipt,
                    &mut number,
                );
                let before = fs::read(&image).unwrap();
                let r = Resources {
                    memory: Budget::new(128 << 20),
                    cancellation: Cancellation::default(),
                };
                let volume = ExtVolume::open(Arc::new(Image(before.clone())), &r).unwrap();
                assert_eq!(volume.geometry().uses_extents(), family == "ext4");
                assert_eq!(volume.geometry().has_journal(), journal);
                let dir = volume.directory(2, 128, 2048, &r).unwrap();
                let file = volume
                    .open_file(
                        dir.entries()
                            .iter()
                            .find(|e| {
                                e.name == partmgr::fs_core::NativeName::Bytes(b"payload".to_vec())
                            })
                            .unwrap()
                            .inode,
                        512,
                        &r,
                    )
                    .unwrap();
                if inode_bytes == 256 {
                    let native = volume
                        .inode(
                            dir.entries()
                                .iter()
                                .find(|e| {
                                    e.name
                                        == partmgr::fs_core::NativeName::Bytes(b"payload".to_vec())
                                })
                                .unwrap()
                                .inode,
                            &r,
                        )
                        .unwrap();
                    let extra = native.raw_extended_metadata();
                    assert!(extra.len() >= 24);
                    assert_eq!(
                        &native.raw_metadata()[16..20],
                        &0x8000_0001u32.to_le_bytes()
                    );
                    assert_eq!(&extra[8..12], &493_827_159u32.to_le_bytes());
                    assert_eq!(&extra[16..20], &0x8000_0001u32.to_le_bytes());
                    assert_eq!(&extra[20..24], &493_827_158u32.to_le_bytes());
                }
                let mut decoded = vec![0; payload.len()];
                assert_eq!(file.read_at(0, &mut decoded, &r).unwrap(), payload.len());
                assert_eq!(decoded, payload);
                for index in 0..64 {
                    let at = (index * 1997) % payload.len();
                    let n = (payload.len() - at).min(17);
                    let mut small = [0; 17];
                    assert_eq!(file.read_at(at as u64, &mut small[..n], &r).unwrap(), n);
                    assert_eq!(&small[..n], &payload[at..at + n]);
                }
                assert_eq!(file.read_at(file.len(), &mut [0; 1], &r).unwrap(), 0);
                if family == "ext4" {
                    let indexed = volume
                        .open_file(
                            dir.entries()
                                .iter()
                                .find(|e| {
                                    e.name
                                        == partmgr::fs_core::NativeName::Bytes(b"indexed".to_vec())
                                })
                                .unwrap()
                                .inode,
                            512,
                            &r,
                        )
                        .unwrap();
                    let mut zero = vec![0x55; 23 * block as usize];
                    indexed.read_at(0, &mut zero, &r).unwrap();
                    assert!(zero.iter().all(|b| *b == 0));
                    let mut ranges = 0;
                    indexed
                        .visit_extents(&r, &mut |_| {
                            ranges += 1;
                            Ok(())
                        })
                        .unwrap();
                    assert!(ranges >= 23);
                }
                let audit = fs_ext_audit::audit(&volume, limits, &r).unwrap();
                assert!(audit.is_clean(), "{stem}: {:?}", audit.findings());
                let owned = audit.owned_blocks();
                drop((audit, file, dir, volume));
                assert_eq!(r.memory.used(), 0);
                let dump = out.join(format!("{stem}-payload.bin"));
                run(
                    "debugfs",
                    vec![
                        "-R".into(),
                        format!("dump /payload {}", dump.display()),
                        image.display().to_string(),
                    ],
                    &mut receipt,
                    &mut number,
                );
                assert_eq!(fs::read(&dump).unwrap(), payload);
                run(
                    "e2fsck",
                    vec!["-fn".into(), image.display().to_string()],
                    &mut receipt,
                    &mut number,
                );
                assert_eq!(fs::read(&image).unwrap(), before);
                if journal {
                    let mapped = run(
                        "debugfs",
                        vec![
                            "-R".into(),
                            "bmap <8> 0".into(),
                            image.display().to_string(),
                        ],
                        &mut receipt,
                        &mut number,
                    );
                    let physical: usize = std::str::from_utf8(&mapped)
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    let header = physical * block as usize;
                    for version in [2, 3] {
                        // Native base image and bmap oracle; independently assemble only
                        // the specified inactive JBD2 checksum feature/header fields.
                        let mut derived = before.clone();
                        derived[header + 40..header + 44].copy_from_slice(
                            &(if version == 2 { 8u32 } else { 16u32 }).to_be_bytes(),
                        );
                        derived[header + 80] = 4;
                        derived[header + 252..header + 256].fill(0);
                        let mut crc = !0u32;
                        for &byte in &derived[header..header + 1024] {
                            crc ^= u32::from(byte.reverse_bits()) << 24;
                            for _ in 0..8 {
                                let high = crc & 0x8000_0000 != 0;
                                crc <<= 1;
                                if high {
                                    crc ^= 0x1edc6f41;
                                }
                            }
                        }
                        derived[header + 252..header + 256]
                            .copy_from_slice(&crc.reverse_bits().to_be_bytes());
                        let derived_path = out.join(format!("{stem}-jbd-csum{version}.img"));
                        fs::write(&derived_path, &derived).unwrap();
                        run(
                            "e2fsck",
                            vec!["-fn".into(), derived_path.display().to_string()],
                            &mut receipt,
                            &mut number,
                        );
                        let checked =
                            ExtVolume::open(Arc::new(Image(derived.clone())), &r).unwrap();
                        let checked_audit = fs_ext_audit::audit(&checked, limits, &r).unwrap();
                        assert!(checked_audit.is_clean(), "{:?}", checked_audit.findings());
                        assert_eq!(checked_audit.owned_blocks(), owned);
                        drop((checked_audit, checked));
                        assert_eq!(r.memory.used(), 0);
                        assert_eq!(fs::read(&derived_path).unwrap(), derived);
                        receipt.push_str(&format!("accepted={stem}-jbd-csum{version} provenance=native-base+independent-forward-CRC32C-header fixture_sha256={:x} journal_header_offset={header} native_e2fsck_readonly=true resource_refund=true\n",Sha256::digest(derived)));
                    }
                }
                receipt.push_str(&format!("accepted={stem} image_sha256={:x} content_sha256={:x} owned_blocks={owned} resource_refund=true native_checks_readonly=true\n",Sha256::digest(before),Sha256::digest(&payload)));
                fs::write(out.join("receipt.txt"), &receipt).unwrap();
            }
        }
    }
    for source in sources {
        assert_eq!(
            fs::read(source).unwrap(),
            fs::read(out.join("sources").join(source)).unwrap(),
            "source changed during gate: {source}"
        );
    }
    receipt.push_str("source_end_matches_start=true\nprofiles=18\nindependent_checksum_derivatives=24\nresult=pass\n");
    fs::write(out.join("receipt.txt"), receipt).unwrap();
    for entry in fs::read_dir(&out).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() {
            fs::File::open(p).unwrap().sync_all().unwrap();
        }
    }
    for dir in ["sources/src", "sources/tests", "sources"] {
        fs::File::open(out.join(dir)).unwrap().sync_all().unwrap();
    }
    fs::File::open(&out).unwrap().sync_all().unwrap();
}
