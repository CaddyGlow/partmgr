//! Independent native legacy structural qualification; no public profile admission.
use super::*;

pub(super) fn read_audit(
    out: &Path,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
) {
    for (profile, family, features) in [
        ("ext3-default", "ext3", None),
        (
            "ext4-gdt16",
            "ext4",
            Some("^metadata_csum,^orphan_file,uninit_bg"),
        ),
        (
            "ext4-absent",
            "ext4",
            Some("^metadata_csum,^orphan_file,^uninit_bg"),
        ),
    ] {
        for bs in [1024usize, 2048, 4096] {
            let stem = format!("native-structural-{profile}-b{bs}");
            let image = out.join(format!("{stem}.img"));
            fs::File::create(&image).unwrap().set_len(16 << 20).unwrap();
            let mut args = vec![
                "-q".into(),
                "-F".into(),
                "-t".into(),
                family.into(),
                "-b".into(),
                bs.to_string(),
                "-I".into(),
                "256".into(),
            ];
            if let Some(features) = features {
                args.extend(["-O".into(), features.into()]);
            }
            args.push(image.display().to_string());
            run(&tools[0], &args, out, receipt, commands, false);
            let expected: Vec<u8> = (0..131089usize).map(|n| (n * 47 + n / 113) as u8).collect();
            let payload = out.join(format!("{stem}-expected.bin"));
            fs::write(&payload, &expected).unwrap();
            let empty = out.join(format!("{stem}-empty.bin"));
            fs::write(&empty, []).unwrap();
            let mut native_commands = format!("write \"{}\" /payload\nea_set /payload user.partmgr {}\nln /payload /alias\nln /payload /native", payload.display(), "z".repeat(600)).into_bytes();
            native_commands.extend_from_slice(b"\xff\nset_inode_field /payload links_count 3\n");
            let mut names = std::collections::BTreeSet::new();
            for n in 0..400 {
                let name = format!("entry{n:03}{}", "n".repeat(247));
                assert_eq!(name.len(), 255);
                names.insert(name.as_bytes().to_vec());
                native_commands.extend_from_slice(
                    format!("write \"{}\" /{name}\n", empty.display()).as_bytes(),
                );
            }
            let command_file = out.join(format!("{stem}-debugfs.txt"));
            fs::write(&command_file, native_commands).unwrap();
            run(
                &tools[1],
                &[
                    "-w".into(),
                    "-f".into(),
                    command_file.display().to_string(),
                    image.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            run(
                &tools[2],
                &["-fyD".into(), image.display().to_string()],
                out,
                receipt,
                commands,
                true,
            );
            run(
                &tools[2],
                &["-fn".into(), image.display().to_string()],
                out,
                receipt,
                commands,
                false,
            );
            let before = fs::read(&image).unwrap();
            let r = Resources {
                memory: Budget::new(64 << 20),
                cancellation: Cancellation::default(),
            };
            let limits = crate::fs_ext_audit::ExtAuditLimits {
                blocks: 16384,
                inodes: 8192,
                work: 8_000_000,
                directory_blocks: 1024,
                directory_entries: 4096,
                findings: 64,
            };
            // Borrow the exclusively locked Storage directly, without an immutable
            // ReadAt alias or any admission into the public volume constructor.
            let storage = FileStorage::open(&image).unwrap();
            let decoder = super::super::super::ExtDecoder::open_legacy_structural_qualification(
                &storage as &dyn Storage,
                18u128 << 64,
                &r,
            )
            .unwrap();
            assert!(!decoder.geometry().has_metadata_checksums());
            assert!(!decoder.geometry().is_classic());
            let proof = decoder.geometry().modern.as_ref().unwrap();
            assert_eq!(
                proof.checksums.has_group_checksum(),
                profile == "ext4-gdt16"
            );
            let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits, &r).unwrap();
            assert!(audit.is_clean(), "{stem} {:?}", audit.findings());
            drop(audit);
            let directory = decoder.directory(2, 1024, 4096, &r).unwrap();
            let mut payload_inode = None;
            let mut alias_inodes = Vec::new();
            for entry in directory.entries() {
                let crate::fs_core::NativeName::Bytes(name) = &entry.name else {
                    panic!("native byte name required");
                };
                if name == b"payload" {
                    payload_inode = Some(entry.inode);
                }
                if name == b"alias" || name == b"native\xff" {
                    alias_inodes.push(entry.inode);
                }
                names.remove(name);
            }
            assert!(names.is_empty());
            let inode = payload_inode.unwrap();
            assert_eq!(alias_inodes, vec![inode; 2]);
            drop(directory);
            let map = decoder.file_map(inode, 2048, &r, false).unwrap();
            let mut copied = vec![0; expected.len()];
            for (n, chunk) in copied.chunks_mut(4093).enumerate() {
                assert_eq!(
                    decoder
                        .read_map(&map, (n * 4093) as u64, chunk, &r)
                        .unwrap(),
                    chunk.len()
                );
            }
            assert_eq!(copied, expected);
            assert_eq!(
                decoder
                    .read_map(&map, copied.len() as u64, &mut [0; 17], &r)
                    .unwrap(),
                0
            );
            drop(map);
            drop(decoder);
            drop(storage);
            assert_eq!(r.memory.used(), 0);
            assert_eq!(fs::read(&image).unwrap(), before);
            let dump = out.join(format!("{stem}-native-payload.bin"));
            let alias_command = out.join(format!("{stem}-alias-dump.txt"));
            let mut raw = b"dump /native\xff \"".to_vec();
            raw.extend_from_slice(dump.display().to_string().as_bytes());
            raw.extend_from_slice(b"\"\n");
            fs::write(&alias_command, raw).unwrap();
            run(
                &tools[1],
                &[
                    "-f".into(),
                    alias_command.display().to_string(),
                    image.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            assert_eq!(fs::read(&dump).unwrap(), expected);
            fs::remove_file(&dump).unwrap();
            run(
                &tools[1],
                &[
                    "-R".into(),
                    format!("dump /payload {}", dump.display()),
                    image.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            assert_eq!(fs::read(&dump).unwrap(), expected);
            receipt.push_str(&format!("validated_native_legacy_structure={stem} profile={profile} block_bytes={bs} native_names=400 hardlink_aliases=2 complete_audit=true public_admission=false image_sha256={:x} payload_sha256={:x}\n", Sha256::digest(before), Sha256::digest(expected)));
            mutate(out, &stem, tools, receipt, commands, inode, &copied);
            namespace_oracle::interruption_profile(
                out,
                tools,
                receipt,
                commands,
                namespace_oracle::DeleteOracle {
                    stem: &format!("{stem}-interruption"),
                    base: &out.join(format!("{stem}-owned-3.img")),
                    deleted_name: b"owned-file",
                    survivor: "/alias",
                    expected: &out.join(format!("{stem}-owned-3-payload.bin")),
                    key: "validated_native_legacy_profile_cut",
                    file_blocks: 2048,
                    directory_blocks: 1024,
                },
            );
        }
    }
}

fn mutate(
    out: &Path,
    stem: &str,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
    inode: u32,
    original: &[u8],
) {
    let image = out.join(format!("{stem}-owned.img"));
    fs::copy(out.join(format!("{stem}.img")), &image).unwrap();
    let r = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 16384,
            inodes: 8192,
            work: 8_000_000,
            directory_blocks: 1024,
            directory_entries: 4096,
            findings: 64,
        },
        file_blocks: 2048,
        affected_blocks: 4096,
        affected_bytes: 8 << 20,
    };
    let planning = crate::fs_ext_edit::ExtEditLimits {
        audit: limits.audit,
        file_blocks: 2048,
        directory_entries: 4096,
        affected_bytes: 8 << 20,
        work: 1_000_000,
        undo: crate::fs_undo::UndoLimits {
            patches: 4096,
            body_bytes: 32 << 20,
        },
    };
    let mut owner = session::Session::open(FileStorage::open(&image).unwrap(), limits, &r).unwrap();
    let append = NativeInput {
        identity: crate::fs_core::ObjectId {
            source: 0xfeed,
            native: b"legacy-owned-append".to_vec(),
            generation: 0,
        },
        bytes: (0..65553).map(|n| (n * 17 + n / 89) as u8).collect(),
    };
    let mut expected = original.to_vec();
    let file_metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100640);
    let dir_metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o40750);
    let child = [crate::fs_core::NativeName::Bytes(b"owned-child".to_vec())];
    let born: Vec<u8> = (0..131089).map(|n| (n * 29 + n / 43) as u8).collect();
    for step in 0..8 {
        let file = owner.file(inode, &r.cancellation).unwrap();
        match step {
            0 => {
                let replacement: Vec<u8> = expected[37..101].iter().map(|n| n ^ 0x57).collect();
                owner
                    .replace(&file, 37, &replacement, &r.cancellation)
                    .unwrap();
                expected[37..101].copy_from_slice(&replacement);
            }
            1 => {
                owner
                    .operate(
                        session::Operation::Extend {
                            file: &file,
                            input: &append,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap();
                expected.extend_from_slice(&append.bytes);
            }
            2 => {
                owner
                    .operate(
                        session::Operation::Truncate {
                            file: &file,
                            length: 513,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap();
                expected.truncate(513);
            }
            3 => {
                owner
                    .operate(
                        session::Operation::CreateFile {
                            parent: &[],
                            name: b"owned-file",
                            metadata: &file_metadata,
                            payload: &born,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap();
            }
            4 => {
                owner
                    .operate(
                        session::Operation::CreateDirectory {
                            parent: &[],
                            name: b"owned-child",
                            metadata: &dir_metadata,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap();
            }
            5 => {
                owner
                    .operate(
                        session::Operation::Rename {
                            source: &[],
                            name: b"owned-file",
                            destination: &child,
                            new_name: b"moved",
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap();
            }
            6 => {
                owner
                    .operate(
                        session::Operation::Delete {
                            parent: &child,
                            name: b"moved",
                            deletion_time: 1234567,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap();
            }
            _ => {
                owner
                    .operate(
                        session::Operation::Delete {
                            parent: &[],
                            name: b"owned-child",
                            deletion_time: 1234567,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap();
            }
        }
        assert!(
            owner
                .read_at(&file, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        let saved = out.join(format!("{stem}-owned-{step}.img"));
        fs::copy(&image, &saved).unwrap();
        run(
            &tools[2],
            &["-fn".into(), saved.display().to_string()],
            out,
            receipt,
            commands,
            false,
        );
        let dump = out.join(format!("{stem}-owned-{step}-payload.bin"));
        run(
            &tools[1],
            &[
                "-R".into(),
                format!("dump /alias {}", dump.display()),
                saved.display().to_string(),
            ],
            out,
            receipt,
            commands,
            false,
        );
        assert_eq!(fs::read(&dump).unwrap(), expected);
        let ea = out.join(format!("{stem}-owned-{step}-xattr.bin"));
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
        assert_eq!(fs::read(ea).unwrap(), vec![b'z'; 600]);
        let created = if matches!(step, 3 | 4) {
            Some("/owned-file")
        } else if step == 5 {
            Some("/owned-child/moved")
        } else {
            None
        };
        if let Some(path) = created {
            let born_dump = out.join(format!("{stem}-owned-{step}-born.bin"));
            run(
                &tools[1],
                &[
                    "-R".into(),
                    format!("dump {path} {}", born_dump.display()),
                    saved.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            assert_eq!(fs::read(born_dump).unwrap(), born);
        }
        receipt.push_str(&format!("validated_native_legacy_owned={stem} step={step} image_sha256={:x} payload_sha256={:x} public_admission=false\n", Sha256::digest(fs::read(saved).unwrap()), Sha256::digest(&expected)));
    }
    let (storage, state) = owner.into_storage();
    assert!(matches!(state, session::State::Ready));
    drop(storage);
    assert_eq!(r.memory.used(), 0);
}
