//! Independently authored e2fsprogs checksum-profile native indirect-map oracles.
use super::*;
pub(super) fn operations(
    out: &Path,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
) {
    profile(out, tools, receipt, commands, false);
}
pub(super) fn legacy256(out: &Path, tools: &[PathBuf], receipt: &mut String, commands: &mut usize) {
    profile(out, tools, receipt, commands, true);
}
fn profile(
    out: &Path,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
    legacy: bool,
) {
    for bs in [1024usize, 2048, 4096] {
        let stem = format!(
            "native-{}-b{bs}",
            if legacy { "legacy256" } else { "indirect" }
        );
        let image = out.join(format!("{stem}.img"));
        fs::File::create(&image).unwrap().set_len(16 << 20).unwrap();
        run(
            &tools[0],
            &[
                "-q".into(),
                "-F".into(),
                "-t".into(),
                if legacy { "ext3" } else { "ext4" }.into(),
                "-b".into(),
                bs.to_string(),
                "-I".into(),
                "256".into(),
                "-O".into(),
                if legacy {
                    "none,has_journal,filetype,sparse_super"
                } else {
                    "^extent,^64bit"
                }
                .into(),
                image.display().to_string(),
            ],
            out,
            receipt,
            commands,
            false,
        );
        let old_len = (12 + bs / 4) * bs - 17;
        let original: Vec<u8> = (0..old_len).map(|n| (n * 43 + n / 13) as u8).collect();
        let original_path = out.join(format!("{stem}-original.bin"));
        fs::write(&original_path, &original).unwrap();
        run(
            &tools[1],
            &[
                "-w".into(),
                "-R".into(),
                format!("write {} /payload", original_path.display()),
                image.display().to_string(),
            ],
            out,
            receipt,
            commands,
            false,
        );
        let mut retained_tail = None;
        let mut native_inode_at = 0;
        if legacy {
            // Independent raw native metadata annotations, without a production encoder.
            let mut bytes = fs::read(&image).unwrap();
            let first = super::super::super::u32le(&bytes, 1024 + 20) as usize;
            let gd = (first + 1) * bs;
            let table = super::super::super::u32le(&bytes, gd + 8) as usize;
            native_inode_at = table * bs + 11 * 256;
            assert_eq!(
                super::super::super::u16le(&bytes, native_inode_at + 128),
                32
            );
            bytes[native_inode_at + 136..native_inode_at + 140]
                .copy_from_slice(&(123456789u32 << 2).to_le_bytes());
            bytes[native_inode_at + 152..native_inode_at + 156]
                .copy_from_slice(&0xa17e0007u32.to_le_bytes());
            retained_tail = Some(bytes[native_inode_at + 128..native_inode_at + 256].to_vec());
            fs::write(
                out.join(format!("{stem}-source-inode.bin")),
                &bytes[native_inode_at..native_inode_at + 256],
            )
            .unwrap();
            fs::write(&image, bytes).unwrap();
        }
        run(
            &tools[2],
            &["-fn".into(), image.display().to_string()],
            out,
            receipt,
            commands,
            false,
        );
        fs::copy(&image, out.join(format!("{stem}-before.img"))).unwrap();
        let r = Resources {
            memory: Budget::new(128 << 20),
            cancellation: Cancellation::default(),
        };
        let limits = session::Limits {
            audit: crate::fs_ext_audit::ExtAuditLimits {
                blocks: 16384,
                inodes: 8192,
                work: 8_000_000,
                directory_blocks: 256,
                directory_entries: 2048,
                findings: 64,
            },
            file_blocks: 2048,
            affected_blocks: 1024,
            affected_bytes: 4 << 20,
        };
        let planning = crate::fs_ext_edit::ExtEditLimits {
            audit: limits.audit,
            file_blocks: 2048,
            directory_entries: 2048,
            affected_bytes: 4 << 20,
            work: if legacy { 1_000_000 } else { 4_000_000 },
            undo: crate::fs_undo::UndoLimits {
                patches: 4096,
                body_bytes: 16 << 20,
            },
        };
        {
            let storage = FileStorage::open(&image).unwrap();
            let (decoder, proof) =
                super::super::super::ExtDecoder::open_native_clean(&storage, 18u128 << 64, &r)
                    .unwrap();
            assert_eq!(decoder.geometry.has_metadata_checksums(), !legacy);
            assert_eq!(decoder.geometry.inode_size, 256);
            assert!(!decoder.geometry.uses_extents());
            if legacy {
                assert!(decoder.geometry.modern.is_none());
            } else {
                assert_eq!(
                    decoder.geometry.modern.as_ref().unwrap().descriptor_size,
                    32
                );
            }
            drop((decoder, proof));
        }
        let mut owner =
            session::Session::open(FileStorage::open(&image).unwrap(), limits, &r).unwrap();
        let input = NativeInput {
            identity: crate::fs_core::ObjectId {
                source: 12345,
                generation: 1,
                native: vec![9],
            },
            bytes: (0..65553).map(|n| (n * 17 + n / 89) as u8).collect(),
        };
        let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100640);
        let directory_metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o40750);
        let payload: Vec<u8> = (0..20000).map(|n| (n * 7 + n / 37) as u8).collect();
        let destination = [crate::fs_core::NativeName::Bytes(b"dir".to_vec())];
        let mut expected = original.clone();
        expected.extend_from_slice(&input.bytes);
        for step in 0..7 {
            match step {
                0 => {
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
                }
                1 => {
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
                                length: 513,
                            },
                            planning,
                            &r.cancellation,
                        )
                        .unwrap();
                }
                2 => owner
                    .operate(
                        session::Operation::CreateFile {
                            parent: &[],
                            name: b"new-direct",
                            metadata: &metadata,
                            payload: &payload,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap(),
                3 => owner
                    .operate(
                        session::Operation::CreateDirectory {
                            parent: &[],
                            name: b"dir",
                            metadata: &directory_metadata,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap(),
                4 => owner
                    .operate(
                        session::Operation::Rename {
                            source: &[],
                            name: b"new-direct",
                            destination: &destination,
                            new_name: b"moved",
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap(),
                5 => owner
                    .operate(
                        session::Operation::Delete {
                            parent: &destination,
                            name: b"moved",
                            deletion_time: 1234567,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap(),
                6 => owner
                    .operate(
                        session::Operation::Delete {
                            parent: &[],
                            name: b"dir",
                            deletion_time: 1234567,
                        },
                        planning,
                        &r.cancellation,
                    )
                    .unwrap(),
                _ => unreachable!(),
            }
            let saved = out.join(format!("{stem}-{step}.img"));
            fs::copy(&image, &saved).unwrap();
            if let Some(tail) = &retained_tail {
                let bytes = fs::read(&saved).unwrap();
                assert_eq!(&bytes[native_inode_at + 128..native_inode_at + 256], tail);
            }
            run(
                &tools[2],
                &["-fn".into(), saved.display().to_string()],
                out,
                receipt,
                commands,
                false,
            );
            let dump = out.join(format!("{stem}-{step}-payload.bin"));
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
            assert_eq!(
                fs::read(&dump).unwrap(),
                if step == 0 {
                    expected.as_slice()
                } else {
                    &original[..513]
                }
            );
            let stat = run(
                &tools[1],
                &[
                    "-R".into(),
                    "stat /payload".into(),
                    saved.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            let stat = String::from_utf8(stat).unwrap();
            assert!(stat.contains("Flags: 0x0"));
            if step == 0 {
                assert!(
                    stat.contains("DIND"),
                    "native append must cross into double-indirect map: {stat}"
                );
            }
            if (2..=4).contains(&step) {
                let name = if step == 4 {
                    "/dir/moved"
                } else {
                    "/new-direct"
                };
                let created = out.join(format!("{stem}-{step}-created.bin"));
                run(
                    &tools[1],
                    &[
                        "-R".into(),
                        format!("dump {name} {}", created.display()),
                        saved.display().to_string(),
                    ],
                    out,
                    receipt,
                    commands,
                    false,
                );
                assert_eq!(fs::read(created).unwrap(), payload);
            }
            let key = if legacy {
                "validated_native_legacy256"
            } else {
                "validated_native_indirect"
            };
            receipt.push_str(&format!("{key}={stem} step={step} block_bytes={bs} old_length={old_len} append_length=65553 image_sha256={:x} payload_sha256={:x}\n",Sha256::digest(fs::read(saved).unwrap()),Sha256::digest(fs::read(dump).unwrap())));
        }
        drop(owner);
        assert_eq!(r.memory.used(), 0);
        if legacy {
            let cut_stem = format!("{stem}-interruption");
            let base = out.join(format!("{cut_stem}-base.img"));
            fs::copy(out.join(format!("{stem}-0.img")), &base).unwrap();
            let survivor = out.join(format!("{cut_stem}-survivor.bin"));
            fs::write(
                &survivor,
                (0..131089usize)
                    .map(|n| (n * 31 + n / 97) as u8)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            run(
                &tools[1],
                &[
                    "-w".into(),
                    "-R".into(),
                    format!("write {} /other", survivor.display()),
                    base.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            run(
                &tools[2],
                &["-fn".into(), base.display().to_string()],
                out,
                receipt,
                commands,
                false,
            );
            super::namespace_oracle::interruption_profile(
                out,
                tools,
                receipt,
                commands,
                super::namespace_oracle::DeleteOracle {
                    stem: &cut_stem,
                    base: &base,
                    deleted_name: b"payload",
                    survivor: "/other",
                    expected: &survivor,
                    key: "validated_native_legacy256_cut",
                    file_blocks: 2048,
                    directory_blocks: 128,
                },
            );
        }
    }
}
