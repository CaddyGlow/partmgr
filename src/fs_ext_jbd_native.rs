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
        "src/fs_ext_jbd_legacy.rs",
        "src/fs_ext_jbd_native.rs",
        "src/fs_ext_jbd_overlay.rs",
        "src/fs_ext_jbd_bootstrap.rs",
        "src/fs_ext_jbd_recovery.rs",
        "src/fs_ext_jbd_transaction.rs",
        "src/fs_ext_jbd_session.rs",
        "src/fs_ext_jbd_modern_plan.rs",
        "src/fs_ext_jbd_modern_extent.rs",
        "src/fs_ext_jbd_modern_htree.rs",
        "src/fs_ext_jbd_modern_indirect.rs",
        "src/fs_ext_jbd_modern_indirect_tests.rs",
        "src/fs_ext_jbd_modern_namespace.rs",
        "src/fs_ext_jbd_modern_inode.rs",
        "src/fs_ext_jbd_modern_namespace_tests.rs",
        "src/fs_ext_jbd_native_namespace.rs",
        "src/fs_ext_jbd_native_indirect.rs",
        "src/fs_ext_jbd_native_legacy.rs",
        "src/fs_ext_integrity.rs",
        "tests/fixtures/fs_ext_legacy_integrity.rs",
        "src/fs_ext_jbd_native_inode.rs",
        "src/fs_ext_jbd_modern_tests.rs",
        "src/fs_ext_edit.rs",
        "src/fs_ext_edit_allocation.rs",
        "src/fs_ext_edit_namespace.rs",
        "src/fs_ext_edit_transaction.rs",
        "src/fs_undo.rs",
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
            for version in [0, 2, 3] {
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
                if version != 0 {
                    put32(&mut journal, 40, 1 | if version == 2 { 8 } else { 16 });
                    journal[80] = 4;
                    put32(&mut journal, 252, 0);
                    let sum = crc(!0, &journal);
                    put32(&mut journal, 252, sum);
                } else {
                    assert_eq!(be32(&journal, 40) & 0x18, 0);
                    assert_eq!(journal[80], 0);
                }
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
                if version != 0 {
                    put32(&mut journal, 252, 0);
                    let sum = crc(!0, &journal);
                    put32(&mut journal, 252, sum);
                }
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
                let recovered_bytes = fs::read(&recovered_image).unwrap();
                let native_header =
                    &recovered_bytes[journal_physical as usize..journal_physical as usize + 1024];
                assert_eq!(&native_header[40..44], &journal[40..44]);
                assert_eq!(native_header[80], journal[80]);
                if version == 0 {
                    assert_eq!(&native_header[252..256], &journal[252..256]);
                }
                receipt.push_str(&format!("validated_journal_profile={stem} physical_bytes={journal_physical} flags={} checksum_type={} legacy_reserved_checksum={}\n",be32(native_header,40),native_header[80],be32(native_header,252)));
                receipt.push_str(&format!(
                    "validated_owned_session={stem} payload_sha256={:x} image_sha256={:x}\n",
                    Sha256::digest(&session_payload),
                    Sha256::digest(fs::read(&recovered_image).unwrap())
                ));
                if family == "ext4" {
                    modern_truncate(&out, &stem, &tools, &mut receipt, &mut commands);
                }
                if family == "ext3" {
                    classic_operations(&out, &stem, bs, &tools, &mut receipt, &mut commands);
                }
                if family == "ext3" && version == 2 {
                    classic_delete_controls(&out, bs, &tools, &mut receipt, &mut commands);
                }
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

struct NativeInput {
    identity: crate::fs_core::ObjectId,
    bytes: Vec<u8>,
}
impl crate::fs_core::FileRead for NativeInput {
    fn identity(&self) -> &crate::fs_core::ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, offset: u64, out: &mut [u8], r: &Resources) -> crate::fs_core::Result<usize> {
        r.cancellation.check()?;
        let at = usize::try_from(offset).unwrap_or(usize::MAX);
        let count = out.len().min(37).min(self.bytes.len().saturating_sub(at));
        if count > 0 {
            out[..count].copy_from_slice(&self.bytes[at..at + count]);
        }
        Ok(count)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visitor: &mut dyn FnMut(crate::fs_core::LogicalExtent) -> crate::fs_core::Result<()>,
    ) -> crate::fs_core::Result<()> {
        r.cancellation.check()?;
        visitor(crate::fs_core::LogicalExtent {
            offset: 0,
            length: self.len(),
            kind: crate::fs_core::ExtentKind::Data,
        })
    }
}
fn classic_operations(
    out: &Path,
    stem: &str,
    bs: usize,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
) {
    use crate::{
        fs_core::{NativeName, ObjectId},
        fs_ext_edit::{ExtCreateMetadata, ExtEditLimits},
        fs_undo::UndoLimits,
    };
    let image = out.join(format!("{stem}-operations.img"));
    fs::copy(out.join(format!("{stem}-owned-recovered.img")), &image).unwrap();
    let r = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 16384,
            inodes: 8192,
            work: 8_000_000,
            directory_blocks: 128,
            directory_entries: 2048,
            findings: 64,
        },
        file_blocks: 512,
        affected_blocks: 512,
        affected_bytes: 4 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 512,
        directory_entries: 2048,
        affected_bytes: 4 << 20,
        work: 100000,
        undo: UndoLimits {
            patches: 4096,
            body_bytes: 16 << 20,
        },
    };
    let mut session =
        session::Session::open(FileStorage::open(&image).unwrap(), limits, &r).unwrap();
    let mut metadata = ExtCreateMetadata::zeroed(0o100640);
    metadata.raw[2..4].copy_from_slice(&123u16.to_le_bytes());
    metadata.raw[24..26].copy_from_slice(&456u16.to_le_bytes());
    for offset in [8, 12, 16] {
        metadata.raw[offset..offset + 4].copy_from_slice(&1234567u32.to_le_bytes());
    }
    let directory_metadata = ExtCreateMetadata::zeroed(0o40750);
    let payload: Vec<u8> = (0..8193)
        .map(|at| ((at * 19 + at / 31) % 256) as u8)
        .collect();
    let input = NativeInput {
        identity: ObjectId {
            source: 123,
            generation: 17,
            native: vec![1],
        },
        bytes: (0..131089)
            .map(|at| ((at * 23 + at / 37) % 256) as u8)
            .collect(),
    };
    let dir = [NativeName::Bytes(b"native-dir".to_vec())];
    let unrelated = fs::read(out.join(format!("{stem}-owned-session-expected.bin"))).unwrap();
    let mut number = 0;
    let mut expected = payload.clone();
    for step in 0..7 {
        let file = if step == 1 || step == 2 {
            Some(session.file(number, &r.cancellation).unwrap())
        } else {
            None
        };
        let operation = match step {
            0 => session::Operation::CreateFile {
                parent: &[],
                name: b"native-new\xff",
                metadata: &metadata,
                payload: &payload,
            },
            1 => session::Operation::Extend {
                file: file.as_ref().unwrap(),
                input: &input,
            },
            2 => session::Operation::Truncate {
                file: file.as_ref().unwrap(),
                length: 513,
            },
            3 => session::Operation::CreateDirectory {
                parent: &[],
                name: b"native-dir",
                metadata: &directory_metadata,
            },
            4 => session::Operation::Rename {
                source: &[],
                name: b"native-new\xff",
                destination: &dir,
                new_name: b"native-moved\xfe",
            },
            5 => session::Operation::Delete {
                parent: &dir,
                name: b"native-moved\xfe",
                deletion_time: 1234567,
            },
            6 => session::Operation::Delete {
                parent: &[],
                name: b"native-dir",
                deletion_time: 1234568,
            },
            _ => unreachable!(),
        };
        session
            .operate(operation, planning, &r.cancellation)
            .unwrap();
        if let Some(file) = &file {
            assert!(
                session
                    .read_at(file, 0, &mut [0; 1], &r.cancellation)
                    .is_err()
            );
        }
        drop(file);
        if step == 0 {
            let file = session
                .file_at(
                    &[NativeName::Bytes(b"native-new\xff".to_vec())],
                    &r.cancellation,
                )
                .unwrap();
            number = file.inode_number();
            drop(file);
        }
        if step == 1 {
            expected.extend_from_slice(&input.bytes);
        }
        if step == 2 {
            expected.truncate(513);
        }
        let saved = out.join(format!("{stem}-operation-{step}.img"));
        fs::copy(&image, &saved).unwrap();
        run(
            &tools[2],
            &["-fn".into(), saved.display().to_string()],
            out,
            receipt,
            commands,
            false,
        );
        let old_dump = out.join(format!("{stem}-operation-{step}-unrelated.bin"));
        run(
            &tools[1],
            &[
                "-R".into(),
                format!("dump /payload {}", old_dump.display()),
                saved.display().to_string(),
            ],
            out,
            receipt,
            commands,
            false,
        );
        assert_eq!(fs::read(&old_dump).unwrap(), unrelated);
        if step < 5 {
            let dump = out.join(format!("{stem}-operation-{step}-payload.bin"));
            run(
                &tools[1],
                &[
                    "-R".into(),
                    format!("dump <{number}> {}", dump.display()),
                    saved.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            assert_eq!(fs::read(&dump).unwrap(), expected);
            fs::write(
                out.join(format!("{stem}-operation-{step}-expected.bin")),
                &expected,
            )
            .unwrap();
            let stat = run(
                &tools[1],
                &[
                    "-R".into(),
                    format!("stat <{number}>"),
                    saved.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            let text = String::from_utf8(stat).unwrap();
            let words: Vec<_> = text.split_whitespace().collect();
            assert!(words.windows(2).any(|pair| pair == ["User:", "123"]));
            assert!(words.windows(2).any(|pair| pair == ["Group:", "456"]));
        }
        receipt.push_str(&format!("validated_native_operation={stem} step={step} block_bytes={bs} image_sha256={:x} unrelated_sha256={:x} payload_sha256={:x}\n",
            Sha256::digest(fs::read(saved).unwrap()), Sha256::digest(&unrelated), Sha256::digest(if step < 5 { &expected[..] } else { &[] })));
    }
    drop(session);
    assert_eq!(r.memory.used(), 0);
}

fn classic_delete_controls(
    out: &Path,
    bs: usize,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
) {
    use crate::fs_ext_edit::{
        ExtEditBinding, ExtEditLimits, ExtEditRegion, ExtEditState, ExtEditor,
    };
    use crate::fs_undo::UndoLimits;
    let seed = out.join(format!("classic-delete-b{bs}-seed.img"));
    fs::File::create(&seed).unwrap().set_len(16 << 20).unwrap();
    run(
        &tools[0],
        &[
            "-q".into(),
            "-F".into(),
            "-t".into(),
            "ext2".into(),
            "-b".into(),
            bs.to_string(),
            "-I".into(),
            "128".into(),
            "-O".into(),
            "none,filetype,sparse_super".into(),
            seed.display().to_string(),
        ],
        out,
        receipt,
        commands,
        false,
    );
    run(
        &tools[1],
        &[
            "-w".into(),
            "-R".into(),
            format!("write {} /victim", out.join("old-payload.bin").display()),
            seed.display().to_string(),
        ],
        out,
        receipt,
        commands,
        false,
    );
    let before = fs::read(&seed).unwrap();
    let boundary = u32::from_le_bytes(before[1024..1028].try_into().unwrap());
    let r = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let limits = ExtEditLimits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 16384,
            inodes: 8192,
            work: 8_000_000,
            directory_blocks: 128,
            directory_entries: 2048,
            findings: 64,
        },
        file_blocks: 512,
        directory_entries: 2048,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: UndoLimits {
            patches: 4096,
            body_bytes: 4 << 20,
        },
    };
    for time in [boundary, 1234567] {
        let image = out.join(format!("classic-delete-b{bs}-t{time}.img"));
        fs::copy(&seed, &image).unwrap();
        let journal = out.join(format!("classic-delete-b{bs}-t{time}.undo"));
        fs::File::create(&journal)
            .unwrap()
            .set_len(4 << 20)
            .unwrap();
        let mut editor = ExtEditor::open(
            FileStorage::open(&image).unwrap(),
            FileStorage::open(&journal).unwrap(),
            ExtEditRegion {
                offset: 0,
                length: 16 << 20,
            },
            ExtEditBinding {
                volume: [0x59; 32],
                generation: 1,
            },
            limits,
            &r,
        )
        .unwrap();
        let root = editor.open_directory(&[], &r).unwrap();
        let file = editor
            .open_file(&[crate::fs_core::NativeName::Bytes(b"victim".to_vec())], &r)
            .unwrap();
        let number = file.inode().number();
        let original_journal = fs::read(&journal).unwrap();
        for invalid_time in [1, boundary - 1] {
            let error = match editor.plan_delete(&root, b"victim", invalid_time, &r) {
                Err(error) => error,
                Ok(_) => panic!("ambiguous native deletion time accepted"),
            };
            assert_eq!(error.kind, ErrorKind::Unsupported);
            assert_eq!(fs::read(&image).unwrap(), before);
            assert_eq!(fs::read(&journal).unwrap(), original_journal);
        }
        let batch = editor.plan_delete(&root, b"victim", time, &r).unwrap();
        assert_eq!(batch.namespace_report().unwrap().deletion_time, Some(time));
        editor.commit(batch, [0x61; 16], &r).unwrap();
        drop((root, file));
        let (target, undo, state) = editor.into_stores();
        assert_eq!(state, ExtEditState::Ready);
        drop((target, undo));
        assert_eq!(r.memory.used(), 0);
        run(
            &tools[2],
            &["-fn".into(), image.display().to_string()],
            out,
            receipt,
            commands,
            false,
        );
        let stat = run(
            &tools[1],
            &[
                "-R".into(),
                format!("stat <{number}>"),
                image.display().to_string(),
            ],
            out,
            receipt,
            commands,
            false,
        );
        let text = String::from_utf8(stat).unwrap();
        assert!(text.contains(&format!("dtime: 0x{time:08x}")), "{text}");
        receipt.push_str(&format!("validated_classic_deletion_boundary=block{bs} time={time} inode_count={boundary} rejected_lower=true image_sha256={:x} journal_sha256={:x}\n", Sha256::digest(fs::read(image).unwrap()), Sha256::digest(fs::read(journal).unwrap())));
    }
}

fn modern_truncate(
    out: &Path,
    stem: &str,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
) {
    let image = out.join(format!("{stem}-modern-truncate.img"));
    fs::copy(out.join(format!("{stem}-owned-recovered.img")), &image).unwrap();
    let setup = out.join(format!("{stem}-modern-fragment.cmds"));
    let mut script = String::new();
    for index in 0..24 {
        script.push_str(&format!(
            "write {} /fragment{index}\n",
            out.join("old-payload.bin").display()
        ));
    }
    for index in (0..24).step_by(2) {
        script.push_str(&format!("rm /fragment{index}\n"));
    }
    let xattr = vec![b'z'; 600];
    script.push_str(&format!(
        "ea_set /payload user.partmgr {}\n",
        String::from_utf8(xattr.clone()).unwrap()
    ));
    script.push_str("mkdir /destination\n");
    fs::write(&setup, script).unwrap();
    run(
        &tools[1],
        &[
            "-w".into(),
            "-f".into(),
            setup.display().to_string(),
            image.display().to_string(),
        ],
        out,
        receipt,
        commands,
        false,
    );
    run(
        &tools[2],
        &["-fn".into(), image.display().to_string()],
        out,
        receipt,
        commands,
        false,
    );
    let before = out.join(format!("{stem}-modern-truncate-before.bin"));
    run(
        &tools[1],
        &[
            "-R".into(),
            format!("dump /payload {}", before.display()),
            image.display().to_string(),
        ],
        out,
        receipt,
        commands,
        false,
    );
    let mut original = fs::read(before).unwrap();
    let r = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 16384,
            inodes: 8192,
            work: 8_000_000,
            directory_blocks: 128,
            directory_entries: 2048,
            findings: 64,
        },
        file_blocks: 1024,
        affected_blocks: 1024,
        affected_bytes: 4 << 20,
    };
    let planning = crate::fs_ext_edit::ExtEditLimits {
        audit: limits.audit,
        file_blocks: 1024,
        directory_entries: 2048,
        affected_bytes: 4 << 20,
        work: 1000000,
        undo: crate::fs_undo::UndoLimits {
            patches: 4096,
            body_bytes: 16 << 20,
        },
    };
    let mut owner = session::Session::open(FileStorage::open(&image).unwrap(), limits, &r).unwrap();
    let input = NativeInput {
        identity: crate::fs_core::ObjectId {
            source: 99,
            generation: 1,
            native: vec![7],
        },
        bytes: (0..655445).map(|n| (n * 23 + n / 41) as u8).collect(),
    };
    let file = owner
        .file_at(
            &[crate::fs_core::NativeName::Bytes(b"payload".to_vec())],
            &r.cancellation,
        )
        .unwrap();
    owner
        .operate(
            session::Operation::Extend {
                file: &file,
                input: &input,
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    drop(file);
    original.extend_from_slice(&input.bytes);
    let stat = run(
        &tools[1],
        &[
            "-R".into(),
            "stat /payload".into(),
            image.display().to_string(),
        ],
        out,
        receipt,
        commands,
        false,
    );
    assert!(
        String::from_utf8(stat).unwrap().contains("ETB0"),
        "native fragmented extension must create indexed extent metadata"
    );

    let saved = out.join(format!("{stem}-modern-extend.img"));
    fs::copy(&image, &saved).unwrap();
    run(
        &tools[2],
        &["-fn".into(), saved.display().to_string()],
        out,
        receipt,
        commands,
        false,
    );
    let dump = out.join(format!("{stem}-modern-extend.bin"));
    run(
        &tools[1],
        &[
            "-R".into(),
            format!("dump /payload {}", dump.display()),
            saved.display().to_string(),
        ],
        out,
        receipt,
        commands,
        false,
    );
    assert_eq!(fs::read(&dump).unwrap(), original);
    let ea = out.join(format!("{stem}-modern-extend-xattr.bin"));
    run(
        &tools[1],
        &[
            "-R".into(),
            format!("ea_get -f {} /payload user.partmgr", ea.display()),
            image.display().to_string(),
        ],
        out,
        receipt,
        commands,
        false,
    );
    assert_eq!(fs::read(&ea).unwrap(), xattr);

    fs::write(
        out.join(format!("{stem}-modern-extend-expected.bin")),
        &original,
    )
    .unwrap();
    receipt.push_str(&format!(
        "validated_modern_extend={stem} image_sha256={:x} payload_sha256={:x}\n",
        Sha256::digest(fs::read(saved).unwrap()),
        Sha256::digest(fs::read(dump).unwrap())
    ));
    for (step, length) in [513u64, 0].into_iter().enumerate() {
        let file = owner
            .file_at(
                &[crate::fs_core::NativeName::Bytes(b"payload".to_vec())],
                &r.cancellation,
            )
            .unwrap();
        owner
            .operate(
                session::Operation::Truncate {
                    file: &file,
                    length,
                },
                planning,
                &r.cancellation,
            )
            .unwrap();
        assert!(
            owner
                .read_at(&file, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        drop(file);
        let saved = out.join(format!("{stem}-modern-truncate-{step}.img"));
        fs::copy(&image, &saved).unwrap();
        run(
            &tools[2],
            &["-fn".into(), saved.display().to_string()],
            out,
            receipt,
            commands,
            false,
        );
        let dump = out.join(format!("{stem}-modern-truncate-{step}.bin"));
        run(
            &tools[1],
            &[
                "-R".into(),
                format!("dump /payload {}", dump.display()),
                saved.display().to_string(),
            ],
            out,
            receipt,
            commands,
            false,
        );
        assert_eq!(fs::read(&dump).unwrap(), original[..length as usize]);
        let ea = out.join(format!("{stem}-modern-truncate-{step}-xattr.bin"));
        run(
            &tools[1],
            &[
                "-R".into(),
                format!("ea_get -f {} /payload user.partmgr", ea.display()),
                saved.display().to_string(),
            ],
            out,
            receipt,
            commands,
            false,
        );
        assert_eq!(fs::read(ea).unwrap(), xattr);
        for index in (1..24).step_by(2) {
            let other = out.join(format!("{stem}-modern-truncate-{step}-fragment{index}.bin"));
            run(
                &tools[1],
                &[
                    "-R".into(),
                    format!("dump /fragment{index} {}", other.display()),
                    saved.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            assert_eq!(
                fs::read(other).unwrap(),
                fs::read(out.join("old-payload.bin")).unwrap()
            );
        }

        fs::write(
            out.join(format!("{stem}-modern-truncate-{step}-expected.bin")),
            &original[..length as usize],
        )
        .unwrap();
        receipt.push_str(&format!("validated_modern_truncate={stem} step={step} length={length} image_sha256={:x} payload_sha256={:x}\n", Sha256::digest(fs::read(saved).unwrap()), Sha256::digest(fs::read(dump).unwrap())));
    }
    let stale = owner
        .file_at(
            &[crate::fs_core::NativeName::Bytes(b"payload".to_vec())],
            &r.cancellation,
        )
        .unwrap();
    let number = stale.inode_number();
    let before = fs::read(&image).unwrap();
    let bs = 1024u32 << u32::from_le_bytes(before[1048..1052].try_into().unwrap());
    let ipg = u32::from_le_bytes(before[1064..1068].try_into().unwrap());
    let first = u32::from_le_bytes(before[1044..1048].try_into().unwrap());
    let inode_size = u16::from_le_bytes(before[1112..1114].try_into().unwrap()) as usize;
    let descriptor_size = u16::from_le_bytes(before[1278..1280].try_into().unwrap()) as usize;
    let descriptor =
        (first as usize + 1) * bs as usize + ((number - 1) / ipg) as usize * descriptor_size;
    let table = u32::from_le_bytes(before[descriptor + 8..descriptor + 12].try_into().unwrap());
    let inode_at = table as usize * bs as usize + ((number - 1) % ipg) as usize * inode_size;
    owner
        .operate(
            session::Operation::Rename {
                source: &[],
                name: b"payload",
                destination: &[],
                new_name: b"renamed",
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    assert!(
        owner
            .read_at(&stale, 0, &mut [0; 1], &r.cancellation)
            .is_err()
    );
    drop(stale);
    let renamed = owner
        .file_at(
            &[crate::fs_core::NativeName::Bytes(b"renamed".to_vec())],
            &r.cancellation,
        )
        .unwrap();
    assert_eq!(renamed.inode_number(), number);
    drop(renamed);
    let after = fs::read(&image).unwrap();
    assert_eq!(
        &before[inode_at..inode_at + inode_size],
        &after[inode_at..inode_at + inode_size]
    );
    let saved = out.join(format!("{stem}-modern-rename.img"));
    fs::write(&saved, &after).unwrap();
    run(
        &tools[2],
        &["-fn".into(), saved.display().to_string()],
        out,
        receipt,
        commands,
        false,
    );
    let dump = out.join(format!("{stem}-modern-rename.bin"));
    run(
        &tools[1],
        &[
            "-R".into(),
            format!("dump /renamed {}", dump.display()),
            saved.display().to_string(),
        ],
        out,
        receipt,
        commands,
        false,
    );
    assert!(fs::read(&dump).unwrap().is_empty());
    let ea = out.join(format!("{stem}-modern-rename-xattr.bin"));
    run(
        &tools[1],
        &[
            "-R".into(),
            format!("ea_get -f {} /renamed user.partmgr", ea.display()),
            saved.display().to_string(),
        ],
        out,
        receipt,
        commands,
        false,
    );
    assert_eq!(fs::read(&ea).unwrap(), xattr);
    fs::write(
        out.join(format!("{stem}-modern-rename-inode.bin")),
        &after[inode_at..inode_at + inode_size],
    )
    .unwrap();
    receipt.push_str(&format!("validated_modern_rename={stem} inode={number} inode_offset={inode_at} inode_size={inode_size} image_sha256={:x} inode_sha256={:x} payload_sha256={:x}\n",Sha256::digest(&after),Sha256::digest(&after[inode_at..inode_at+inode_size]),Sha256::digest(fs::read(dump).unwrap())));
    drop(owner);
    assert_eq!(r.memory.used(), 0);
    namespace_oracle::operations(out, stem, tools, receipt, commands);
    if stem == "ext4-b1024-v3" {
        namespace_oracle::interruption(out, stem, tools, receipt, commands);
        namespace_oracle::indexed_operations(out, stem, tools, receipt, commands);
        namespace_oracle::shared_ea_hardlinks(out, stem, tools, receipt, commands);
        indirect_oracle::operations(out, tools, receipt, commands);
        inode_oracle::operations(out, tools, receipt, commands);
        indirect_oracle::legacy256(out, tools, receipt, commands);
        legacy_integrity_oracle::read_audit(out, tools, receipt, commands);
    }
}

#[path = "fs_ext_jbd_native_namespace.rs"]
mod namespace_oracle;

#[path = "fs_ext_jbd_native_indirect.rs"]
mod indirect_oracle;
#[path = "fs_ext_jbd_native_legacy.rs"]
mod legacy_integrity_oracle;

#[path = "fs_ext_jbd_native_inode.rs"]
mod inode_oracle;
