//! Independent e2fsprogs replay oracle for the staged native transaction codec.
use super::*;
use crate::{
    fs_core::{Budget, Cancellation},
    storage::{FileStorage, Storage},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
fn crc(mut state: u32, bytes: &[u8]) -> u32 {
    state = state.reverse_bits();
    for byte in bytes {
        state ^= u32::from(byte.reverse_bits()) << 24;
        for _ in 0..8 {
            state = (state << 1)
                ^ if state & 0x80000000 != 0 {
                    0x1edc6f41
                } else {
                    0
                };
        }
    }
    state.reverse_bits()
}
fn capsule_original(encoded: &EncodedTransaction) -> [u8; 1024] {
    let mut bytes = [0; 1024];
    bytes[..512].copy_from_slice(&encoded.blocks[0].bytes[128..640]);
    bytes[512..].copy_from_slice(&encoded.blocks[2].bytes[128..640]);
    bytes
}
fn write_exact(storage: &mut impl Storage, mut at: u64, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let count = storage.write_at(at, bytes).unwrap();
        assert!(count > 0 && count <= bytes.len());
        at += count as u64;
        bytes = &bytes[count..];
    }
}
fn run(
    tool: &Path,
    args: &[String],
    out: &Path,
    receipt: &mut String,
    count: &mut usize,
    repair: bool,
) -> Vec<u8> {
    let output = Command::new(tool).args(args).output().unwrap();
    let stem = format!("command-{:04}", *count);
    *count += 1;
    for (name, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        fs::write(out.join(format!("{stem}.{name}")), bytes).unwrap();
    }
    receipt.push_str(&format!("command={} args={args:?} status={} stdout={stem}.stdout sha256={:x} stderr={stem}.stderr sha256={:x}\n",
        tool.display(), output.status, Sha256::digest(&output.stdout), Sha256::digest(&output.stderr)));
    assert!(
        output.status.success() || repair && output.status.code() == Some(1),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
#[test]
#[ignore = "explicit staged native JBD2 codec replay oracle; fresh PARTMGR_EXT_JBD_EVIDENCE and native tools required"]
fn native_jbd2_codec_e2fsck_replay_and_payload() {
    let out = PathBuf::from(
        std::env::var_os("PARTMGR_EXT_JBD_EVIDENCE")
            .expect("enabled native oracle requires evidence destination"),
    );
    assert!(out.is_absolute());
    fs::create_dir(&out).expect("fresh evidence destination required");
    let mut receipt = "scope=test-only bounded native JBD2 codec; not an owned editor/recovery acceptance claim\n".to_string();
    let source_names = [
        "src/fs_ext.rs",
        "src/fs_ext_jbd.rs",
        "src/fs_ext_jbd_native.rs",
        "src/fs_ext_jbd_overlay.rs",
        "src/fs_ext_jbd_bootstrap.rs",
        "src/fs_ext_jbd_recovery.rs",
        "src/fs_ext_jbd_transaction.rs",
        "src/fs_ext_jbd_session.rs",
        "src/fs_ext_journal.rs",
        "src/fs_ext_extent.rs",
        "src/fs_ext_checksum.rs",
        "src/fs_ext_metadata.rs",
        "src/fs_ext_modern.rs",
        "src/fs_ext_directory.rs",
        "src/fs_ext_hash.rs",
        "src/fs_ext_resize.rs",
        "src/fs_ext_xattr.rs",
        "src/fs_ext_audit.rs",
        "src/fs_core.rs",
        "src/fs_file.rs",
        "src/storage.rs",
        "Cargo.lock",
    ];
    for name in source_names {
        let bytes = fs::read(name).unwrap();
        let target = out.join("sources").join(name);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, &bytes).unwrap();
        receipt.push_str(&format!(
            "source={name} sha256={:x}\n",
            Sha256::digest(bytes)
        ));
    }
    let binary = fs::read(std::env::current_exe().unwrap()).unwrap();
    fs::write(out.join("gate-binary"), &binary).unwrap();
    receipt.push_str(&format!("binary_sha256={:x}\n", Sha256::digest(binary)));
    let mut tools = Vec::new();
    let mut commands = 0;
    for name in ["mke2fs", "debugfs", "e2fsck"] {
        let tool = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|p| p.join(name))
            .find(|p| p.is_file())
            .expect("enabled gate requires native tool");
        receipt.push_str(&format!(
            "tool={name} path={} sha256={:x}\n",
            tool.display(),
            Sha256::digest(fs::read(&tool).unwrap())
        ));
        run(
            &tool,
            &["-V".into()],
            &out,
            &mut receipt,
            &mut commands,
            false,
        );
        tools.push(tool);
    }
    let payload: Vec<u8> = (0..131089usize)
        .map(|n| ((n * 71 + n / 251) % 256) as u8)
        .collect();
    fs::write(out.join("old-payload.bin"), &payload).unwrap();
    let mut expected = payload.clone();
    for (at, byte) in expected.iter_mut().enumerate() {
        *byte ^= ((at / 37) as u8).wrapping_add(1);
    }
    expected[..4].copy_from_slice(&MAGIC.to_be_bytes());
    fs::write(out.join("new-payload.bin"), &expected).unwrap();
    for bs in [1024usize, 2048, 4096] {
        for family in ["ext3", "ext4"] {
            for version in [2, 3] {
                let stem = format!("{family}-b{bs}-v{version}");
                let image = out.join(format!("{stem}.img"));
                fs::File::create(&image).unwrap().set_len(16 << 20).unwrap();
                let mut args = vec![
                    "-q".into(),
                    "-F".into(),
                    "-t".into(),
                    family.into(),
                    "-b".into(),
                    bs.to_string(),
                ];
                if family == "ext3" {
                    args.extend([
                        "-I".into(),
                        "128".into(),
                        "-O".into(),
                        "none,has_journal,filetype,sparse_super".into(),
                    ]);
                }
                args.push(image.display().to_string());
                run(&tools[0], &args, &out, &mut receipt, &mut commands, false);
                run(
                    &tools[1],
                    &[
                        "-w".into(),
                        "-R".into(),
                        format!("write {} /payload", out.join("old-payload.bin").display()),
                        image.display().to_string(),
                    ],
                    &out,
                    &mut receipt,
                    &mut commands,
                    false,
                );
                let mapped = run(
                    &tools[1],
                    &[
                        "-R".into(),
                        "bmap <8> 0".into(),
                        image.display().to_string(),
                    ],
                    &out,
                    &mut receipt,
                    &mut commands,
                    false,
                );
                let journal_physical: u64 = String::from_utf8(mapped)
                    .unwrap()
                    .trim()
                    .parse::<u64>()
                    .unwrap()
                    * bs as u64;
                // Independently author only the specified inactive checksum profile.
                // This is fixture preparation, not a writer feature-upgrade claim.
                let mut storage = FileStorage::open(&image).unwrap();
                if bs > 1024 {
                    // A journal-magic boot prefix independently exercises native
                    // escaping of full block-zero superblock redo and fences.
                    write_exact(&mut storage, 0, &MAGIC.to_be_bytes());
                }
                let mut journal = [0u8; 1024];
                storage
                    .read_exact_at(journal_physical, &mut journal)
                    .unwrap();
                assert_eq!(be32(&journal, 28), 0);
                put32(&mut journal, 40, 1 | if version == 2 { 8 } else { 16 });
                journal[80] = 4;
                put32(&mut journal, 252, 0);
                let sum = crc(!0, &journal);
                put32(&mut journal, 252, sum);
                write_exact(&mut storage, journal_physical, &journal);
                storage.flush().unwrap();
                drop(storage);
                run(
                    &tools[2],
                    &["-fn".into(), image.display().to_string()],
                    &out,
                    &mut receipt,
                    &mut commands,
                    false,
                );
                let mut storage = FileStorage::open(&image).unwrap();
                let r = Resources {
                    memory: Budget::new(16 << 20),
                    cancellation: Cancellation::default(),
                };
                let (decoder, mut proof) =
                    super::super::ExtDecoder::open_native_clean(&storage, 18u128 << 64, &r)
                        .unwrap();
                let audit = crate::fs_ext_audit::audit_decoder(
                    &decoder,
                    crate::fs_ext_audit::ExtAuditLimits {
                        blocks: 16384,
                        inodes: 8192,
                        work: 8_000_000,
                        directory_blocks: 128,
                        directory_entries: 2048,
                        findings: 64,
                    },
                    &r,
                )
                .unwrap();
                assert!(audit.is_clean());
                let directory = decoder.directory(2, 64, 128, &r).unwrap();
                let number = directory
                    .entries()
                    .iter()
                    .find(|e| e.name == crate::fs_core::NativeName::Bytes(b"payload".to_vec()))
                    .unwrap()
                    .inode;
                let file = decoder.file_map(number, 256, &r, false).unwrap();
                let mut input = Vec::new();
                for (index, chunk) in expected.chunks(bs).enumerate() {
                    let position = index as u64 * bs as u64;
                    let extent = file
                        .extents
                        .iter()
                        .find(|e| e.offset <= position && position < e.offset + e.length)
                        .unwrap();
                    let super::super::ExtentKind::Data(at) = extent.kind else {
                        panic!("native payload hole")
                    };
                    let physical = at + position - extent.offset;
                    let mut bytes = [0; MAX_BLOCK];
                    storage.read_exact_at(physical, &mut bytes[..bs]).unwrap();
                    bytes[..chunk.len()].copy_from_slice(chunk);
                    input.push(ReplayBlock {
                        destination: (physical / bs as u64) as u32,
                        bytes,
                    });
                }
                drop((file, directory, audit, decoder));
                proof.geometry.start = proof.geometry.first;
                let preparation_geometry = proof.geometry;
                let mut primary_block = vec![0; bs];
                storage
                    .read_exact_at(if bs == 1024 { 1024 } else { 0 }, &mut primary_block)
                    .unwrap();
                let prepared = prepare(&proof.geometry, &primary_block, &journal, &r).unwrap();
                publish_log(&mut storage, &proof, &prepared, &r).unwrap();
                let capsule = preparation(&preparation_geometry, &r, |logical, bytes| {
                    storage.read_exact_at(proof.physical(logical)?, bytes)
                })
                .unwrap();
                assert_eq!(capsule.journal_superblock, journal);
                assert_eq!(capsule.next_logical, prepared.next_logical);
                drop(capsule);
                proof.geometry.start = prepared.next_logical;
                proof.geometry.sequence = proof.geometry.sequence.wrapping_add(1);
                let encoded = encode(&proof.geometry, &input, 100_000, &r, |_| Ok(())).unwrap();
                publish_log(&mut storage, &proof, &encoded, &r).unwrap();
                // Native committed log is activated, then the ext RECOVER bit is set.
                // Ordered dirty-bootstrap/fault publication is a later session layer.
                put32(&mut journal, 28, preparation_geometry.first);
                put32(&mut journal, 252, 0);
                let sum = crc(!0, &journal);
                put32(&mut journal, 252, sum);
                write_exact(&mut storage, journal_physical, &journal);
                storage.flush().unwrap();
                let mut superblock = [0u8; 1024];
                storage.read_exact_at(1024, &mut superblock).unwrap();
                let features = u32::from_le_bytes(superblock[96..100].try_into().unwrap()) | 4;
                superblock[96..100].copy_from_slice(&features.to_le_bytes());
                let ro = u32::from_le_bytes(superblock[100..104].try_into().unwrap());
                if ro & 0x400 != 0 {
                    let sum = crc(!0, &superblock[..1020]);
                    superblock[1020..].copy_from_slice(&sum.to_le_bytes());
                }
                write_exact(&mut storage, 1024, &superblock);
                storage.flush().unwrap();
                let bootstrap = bootstrap::Bootstrap::read(&storage, 65536, 8_000_000, &r).unwrap();
                assert_eq!(bootstrap.primary, superblock);
                assert_eq!(bootstrap.journal, journal);
                assert_eq!(
                    bootstrap.inode_bytes,
                    if family == "ext3" { 128 } else { 256 }
                );
                assert_eq!(super::super::u16le(&bootstrap.inode, 0) & 0xf000, 0x8000);
                assert_eq!(
                    bootstrap.physical_blocks.len(),
                    proof.geometry.maximum as usize
                );
                if family == "ext3" {
                    assert!(!bootstrap.metadata_blocks.is_empty());
                }
                for logical in 0..bootstrap.geometry.maximum {
                    assert_eq!(
                        bootstrap.physical(logical).unwrap(),
                        proof.physical(logical).unwrap()
                    );
                }
                let replay = scan(
                    &bootstrap.geometry,
                    256,
                    100_000,
                    &r,
                    |logical, bytes| storage.read_exact_at(bootstrap.physical(logical)?, bytes),
                    |physical| bootstrap.destination(physical),
                )
                .unwrap();
                assert_eq!(replay.committed_transactions, 2);
                let closed = preparation(&preparation_geometry, &r, |logical, bytes| {
                    storage.read_exact_at(bootstrap.physical(logical)?, bytes)
                })
                .unwrap();
                bootstrap
                    .validate_preparation(&closed, replay.next_sequence)
                    .unwrap();
                drop(closed);
                let view = overlay::Overlay::new(
                    &storage,
                    &replay.blocks,
                    bs,
                    Some(overlay::JournalControl {
                        physical: journal_physical,
                        original: capsule_original(&prepared),
                        geometry: preparation_geometry,
                        next_sequence: replay.next_sequence,
                    }),
                    &r,
                )
                .unwrap();
                let verified = view
                    .verify(
                        18u128 << 64,
                        crate::fs_ext_audit::ExtAuditLimits {
                            blocks: 16384,
                            inodes: 8192,
                            work: 8_000_000,
                            directory_blocks: 128,
                            directory_entries: 2048,
                            findings: 64,
                        },
                        Some(&bootstrap),
                    )
                    .unwrap();
                drop((
                    verified, replay, bootstrap, encoded, prepared, proof, storage,
                ));
                assert_eq!(r.memory.used(), 0);
                let before = fs::read(&image).unwrap();
                fs::write(out.join(format!("{stem}-committed-log.img")), &before).unwrap();
                let recovered_image = out.join(format!("{stem}-owned-recovered.img"));
                fs::write(&recovered_image, &before).unwrap();
                let mut owned_recovery = FileStorage::open(&recovered_image).unwrap();
                let outcome = recovery::recover(
                    &mut owned_recovery,
                    18u128 << 64,
                    crate::fs_ext_audit::ExtAuditLimits {
                        blocks: 16384,
                        inodes: 8192,
                        work: 8_000_000,
                        directory_blocks: 128,
                        directory_entries: 2048,
                        findings: 64,
                    },
                    256,
                    &r,
                )
                .unwrap();
                assert_eq!(outcome.transactions, 2);
                assert!(outcome.blocks > 1);
                assert_eq!(
                    outcome.next_sequence,
                    preparation_geometry.sequence.wrapping_add(2)
                );
                let published = transaction::commit(
                    &mut owned_recovery,
                    18u128 << 64,
                    crate::fs_ext_audit::ExtAuditLimits {
                        blocks: 16384,
                        inodes: 8192,
                        work: 8_000_000,
                        directory_blocks: 128,
                        directory_entries: 2048,
                        findings: 64,
                    },
                    256,
                    1 << 20,
                    &input,
                    &r,
                )
                .unwrap();
                assert_eq!(published.transactions, 2);
                assert_eq!(
                    published.next_sequence,
                    preparation_geometry.sequence.wrapping_add(4)
                );
                let mut session = session::Session::open(
                    owned_recovery,
                    session::Limits {
                        audit: crate::fs_ext_audit::ExtAuditLimits {
                            blocks: 16384,
                            inodes: 8192,
                            work: 8_000_000,
                            directory_blocks: 128,
                            directory_entries: 2048,
                            findings: 64,
                        },
                        file_blocks: 256,
                        affected_blocks: 256,
                        affected_bytes: 1 << 20,
                    },
                    &r,
                )
                .unwrap();
                let handle = session.file(number, &r.cancellation).unwrap();
                let mut small = [0; 64];
                assert_eq!(
                    session
                        .read_at(&handle, 37, &mut small, &r.cancellation)
                        .unwrap(),
                    64
                );
                assert_eq!(small, expected[37..101]);
                let mut session_payload = expected.clone();
                for byte in &mut session_payload[37..101] {
                    *byte ^= 0x57;
                }
                session
                    .replace(&handle, 37, &session_payload[37..101], &r.cancellation)
                    .unwrap();
                assert!(
                    session
                        .read_at(&handle, 0, &mut small, &r.cancellation)
                        .is_err()
                );
                let fresh = session.file(number, &r.cancellation).unwrap();
                assert_eq!(fresh.identity.source, handle.identity.source);
                assert_ne!(fresh.identity.generation, handle.identity.generation);
                session.recover(&r.cancellation).unwrap();
                assert!(
                    session
                        .read_at(&fresh, 0, &mut small, &r.cancellation)
                        .is_err()
                );
                drop((handle, fresh));
                let (owned_recovery, state) = session.into_storage();
                assert_eq!(state, session::State::Ready);
                drop(owned_recovery);
                if bs > 1024 {
                    assert_eq!(
                        &fs::read(&recovered_image).unwrap()[..4],
                        &MAGIC.to_be_bytes()
                    );
                }
                assert_eq!(r.memory.used(), 0);
                run(
                    &tools[2],
                    &["-fn".into(), recovered_image.display().to_string()],
                    &out,
                    &mut receipt,
                    &mut commands,
                    false,
                );
                let recovered_dump = out.join(format!("{stem}-owned-recovered-payload.bin"));
                run(
                    &tools[1],
                    &[
                        "-R".into(),
                        format!("dump /payload {}", recovered_dump.display()),
                        recovered_image.display().to_string(),
                    ],
                    &out,
                    &mut receipt,
                    &mut commands,
                    false,
                );
                assert_eq!(fs::read(&recovered_dump).unwrap(), session_payload);
                fs::write(
                    out.join(format!("{stem}-owned-session-expected.bin")),
                    &session_payload,
                )
                .unwrap();
                receipt.push_str(&format!(
                    "validated_owned_session={stem} payload_sha256={:x} image_sha256={:x}\n",
                    Sha256::digest(&session_payload),
                    Sha256::digest(fs::read(&recovered_image).unwrap())
                ));
                run(
                    &tools[2],
                    &["-fy".into(), image.display().to_string()],
                    &out,
                    &mut receipt,
                    &mut commands,
                    true,
                );
                run(
                    &tools[2],
                    &["-fn".into(), image.display().to_string()],
                    &out,
                    &mut receipt,
                    &mut commands,
                    false,
                );
                let dump = out.join(format!("{stem}-payload.bin"));
                run(
                    &tools[1],
                    &[
                        "-R".into(),
                        format!("dump /payload {}", dump.display()),
                        image.display().to_string(),
                    ],
                    &out,
                    &mut receipt,
                    &mut commands,
                    false,
                );
                assert!(
                    fs::read(&dump).unwrap() == expected,
                    "native replay payload mismatch: {stem}"
                );
                if bs > 1024 {
                    assert_eq!(&fs::read(&image).unwrap()[..4], &MAGIC.to_be_bytes());
                }
                receipt.push_str(&format!("validated={stem} native_replay=true payload_sha256={:x} image_sha256={:x} committed_log_sha256={:x}\n", Sha256::digest(&expected), Sha256::digest(fs::read(&image).unwrap()), Sha256::digest(before)));
            }
        }
    }
    for name in source_names {
        assert_eq!(
            fs::read(name).unwrap(),
            fs::read(out.join("sources").join(name)).unwrap(),
            "source changed: {name}"
        );
    }
    receipt.push_str("source_end_matches_start=true\nresult=pass\n");
    fs::write(out.join("receipt.txt"), receipt).unwrap();
}
