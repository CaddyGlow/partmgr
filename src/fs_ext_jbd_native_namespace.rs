//! Independent e2fsprogs namespace/payload oracles for the private owned session.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

pub(super) fn operations(
    out: &Path,
    stem: &str,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
) {
    let image = out.join(format!("{stem}-modern-truncate.img"));
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
        work: 1_000_000,
        undo: crate::fs_undo::UndoLimits {
            patches: 4096,
            body_bytes: 16 << 20,
        },
    };
    let mut owner = session::Session::open(FileStorage::open(&image).unwrap(), limits, &r).unwrap();
    let payload: Vec<u8> = (0..131089).map(|n| (n * 29 + n / 43) as u8).collect();
    fs::write(out.join(format!("{stem}-namespace-expected.bin")), &payload).unwrap();
    let mut metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100640);
    metadata.raw[2..4].copy_from_slice(&1000u16.to_le_bytes());
    metadata.raw[24..26].copy_from_slice(&1001u16.to_le_bytes());
    let directory_metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o40750);
    let newdir = [crate::fs_core::NativeName::Bytes(b"newdir".to_vec())];
    let destination = [crate::fs_core::NativeName::Bytes(b"destination".to_vec())];
    let nested = [
        destination[0].clone(),
        crate::fs_core::NativeName::Bytes(b"nested".to_vec()),
    ];
    let steps = [
        session::Operation::CreateFile {
            parent: &[],
            name: b"newfile",
            metadata: &metadata,
            payload: &payload,
        },
        session::Operation::CreateDirectory {
            parent: &[],
            name: b"newdir",
            metadata: &directory_metadata,
        },
        session::Operation::Rename {
            source: &[],
            name: b"newfile",
            destination: &newdir,
            new_name: b"moved",
        },
        session::Operation::Rename {
            source: &[],
            name: b"newdir",
            destination: &destination,
            new_name: b"nested",
        },
        session::Operation::Delete {
            parent: &nested,
            name: b"moved",
            deletion_time: 1234567,
        },
        session::Operation::Delete {
            parent: &destination,
            name: b"nested",
            deletion_time: 1234567,
        },
        session::Operation::Delete {
            parent: &[],
            name: b"renamed",
            deletion_time: 1234567,
        },
    ];
    for (step, operation) in steps.into_iter().enumerate() {
        if step == 3 {
            let before = fs::read(&image).unwrap();
            assert_eq!(
                owner
                    .operate(
                        session::Operation::Rename {
                            source: &[],
                            name: b"newdir",
                            destination: &newdir,
                            new_name: b"cycle"
                        },
                        planning,
                        &r.cancellation
                    )
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(fs::read(&image).unwrap(), before);
            receipt.push_str(&format!(
                "validated_modern_prewrite_control={stem} kind=directory_cycle image_sha256={:x}\n",
                Sha256::digest(before)
            ));
        }
        if step == 4 {
            let before = fs::read(&image).unwrap();
            assert_eq!(
                owner
                    .operate(
                        session::Operation::Delete {
                            parent: &destination,
                            name: b"nested",
                            deletion_time: 1234567
                        },
                        planning,
                        &r.cancellation
                    )
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::DirectoryNotEmpty
            );
            assert_eq!(fs::read(&image).unwrap(), before);
            receipt.push_str(&format!("validated_modern_prewrite_control={stem} kind=nonempty_directory image_sha256={:x}\n",Sha256::digest(before)));
        }
        owner.operate(operation, planning, &r.cancellation).unwrap();
        let saved = out.join(format!("{stem}-namespace-{step}.img"));
        fs::copy(&image, &saved).unwrap();
        run(
            &tools[2],
            &["-fn".into(), saved.display().to_string()],
            out,
            receipt,
            commands,
            false,
        );
        let expected_path = match step {
            0 | 1 => Some("/newfile"),
            2 => Some("/newdir/moved"),
            3 => Some("/destination/nested/moved"),
            _ => None,
        };
        let hash = if let Some(path) = expected_path {
            let dump = out.join(format!("{stem}-namespace-{step}.bin"));
            run(
                &tools[1],
                &[
                    "-R".into(),
                    format!("dump {path} {}", dump.display()),
                    saved.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            let bytes = fs::read(&dump).unwrap();
            assert_eq!(bytes, payload);
            let stat = run(
                &tools[1],
                &[
                    "-R".into(),
                    format!("stat {path}"),
                    saved.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            let text = String::from_utf8(stat).unwrap();
            assert!(
                text.contains("User:  1000") && text.contains("Group:  1001"),
                "{text}"
            );
            Sha256::digest(bytes)
        } else {
            Sha256::digest([])
        };
        if step < 6 {
            let ea = out.join(format!("{stem}-namespace-{step}-xattr.bin"));
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
            assert_eq!(fs::read(ea).unwrap(), vec![b'z'; 600]);
        }
        for index in (1..24).step_by(2) {
            let dump = out.join(format!("{stem}-namespace-{step}-fragment{index}.bin"));
            run(
                &tools[1],
                &[
                    "-R".into(),
                    format!("dump /fragment{index} {}", dump.display()),
                    saved.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            assert_eq!(
                fs::read(dump).unwrap(),
                fs::read(out.join("old-payload.bin")).unwrap()
            );
        }
        receipt.push_str(&format!("validated_modern_namespace={stem} step={step} image_sha256={:x} payload_sha256={hash:x}\n",Sha256::digest(fs::read(saved).unwrap())));
    }
    drop(owner);
    assert_eq!(r.memory.used(), 0);
}

// Each retained delta reconstructs an exact interrupted image from the immutable
// native fixture. This keeps an exhaustive gate from retaining hundreds of copies
// of unrelated free space; offsets are evidence, never an editing API.
fn retain_delta(path: &Path, base: &[u8], changed: &[u8]) {
    assert_eq!(base.len(), changed.len());
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"EXTCUT01");
    encoded.extend_from_slice(&(base.len() as u64).to_le_bytes());
    encoded.extend_from_slice(&Sha256::digest(base));
    let mut at = 0;
    while at < base.len() {
        if base[at] == changed[at] {
            at += 1;
            continue;
        }
        let begin = at;
        while at < base.len() && base[at] != changed[at] {
            at += 1;
        }
        encoded.extend_from_slice(&(begin as u64).to_le_bytes());
        encoded.extend_from_slice(&((at - begin) as u64).to_le_bytes());
        encoded.extend_from_slice(&changed[begin..at]);
    }
    fs::write(path, encoded).unwrap();
}

pub(super) fn interruption(
    out: &Path,
    stem: &str,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
) {
    let base = out.join(format!("{stem}-namespace-0.img"));
    let expected = out.join("old-payload.bin");
    interruption_profile(
        out,
        tools,
        receipt,
        commands,
        DeleteOracle {
            stem,
            base: &base,
            deleted_name: b"newfile",
            survivor: "/fragment1",
            expected: &expected,
            key: "validated_native_cut",
            file_blocks: 1024,
            directory_blocks: 128,
        },
    );
}

pub(super) struct DeleteOracle<'a> {
    pub(super) stem: &'a str,
    pub(super) base: &'a Path,
    pub(super) deleted_name: &'a [u8],
    pub(super) survivor: &'a str,
    pub(super) expected: &'a Path,
    pub(super) key: &'a str,
    pub(super) file_blocks: usize,
    pub(super) directory_blocks: usize,
}

pub(super) fn interruption_profile(
    out: &Path,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
    model: DeleteOracle<'_>,
) {
    let stem = model.stem;
    let base = fs::read(model.base).unwrap();
    let expected = fs::read(model.expected).unwrap();
    let r = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 16384,
            inodes: 8192,
            work: 8_000_000,
            directory_blocks: model.directory_blocks,
            directory_entries: 2048,
            findings: 64,
        },
        file_blocks: model.file_blocks,
        affected_blocks: 1024,
        affected_bytes: 4 << 20,
    };
    let planning = crate::fs_ext_edit::ExtEditLimits {
        audit: limits.audit,
        file_blocks: model.file_blocks,
        directory_entries: 2048,
        affected_bytes: 4 << 20,
        work: 1_000_000,
        undo: crate::fs_undo::UndoLimits {
            patches: 4096,
            body_bytes: 16 << 20,
        },
    };
    let make = |immediate, failed_flush_persists, torn, cut| recovery::tests::Fault {
        visible: base.clone(),
        durable: base.clone(),
        events: 0,
        immediate,
        failed_flush_persists,
        torn,
        cut,
    };
    let perform = |owner: &mut session::Session<recovery::tests::Fault>| {
        owner.operate(
            session::Operation::Delete {
                parent: &[],
                name: model.deleted_name,
                deletion_time: 1234567,
            },
            planning,
            &r.cancellation,
        )
    };
    let mut owner =
        session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
    perform(&mut owner).unwrap();
    let (success, _) = owner.into_storage();
    let boot =
        bootstrap::Bootstrap::read(&success, limits.audit.blocks, limits.audit.work, &r).unwrap();
    let journal_blocks = boot.physical_blocks.clone();
    let bs = boot.geometry.block_bytes;
    drop(boot);
    fs::write(
        out.join(format!("{stem}-cut-success.img")),
        &success.durable,
    )
    .unwrap();
    for immediate in [false, true] {
        for failed_flush_persists in [false, true] {
            for torn in [false, true] {
                for cut in 1..=success.events {
                    let label =
                        format!("{stem}-cut-{immediate}-{failed_flush_persists}-{torn}-{cut}");
                    let mut owner = session::Session::open(
                        make(immediate, failed_flush_persists, torn, cut),
                        limits,
                        &r,
                    )
                    .unwrap();
                    assert!(perform(&mut owner).is_err());
                    let (mut target, _) = owner.into_storage();
                    assert_eq!(r.memory.used(), 0);
                    retain_delta(
                        &out.join(format!("{label}-interrupted.delta")),
                        &base,
                        &target.durable,
                    );
                    target.visible.clone_from(&target.durable);
                    target.cut = usize::MAX;
                    recovery::recover(
                        &mut target,
                        18u128 << 64,
                        limits.audit,
                        limits.affected_blocks + 1,
                        &r,
                    )
                    .unwrap();
                    let home_matches = |expected: &[u8]| {
                        target
                            .durable
                            .chunks_exact(bs)
                            .zip(expected.chunks_exact(bs))
                            .enumerate()
                            .all(|(block, (actual, expected))| {
                                journal_blocks.contains(&(block as u32)) || actual == expected
                            })
                    };
                    let old = home_matches(&base);
                    assert!(
                        old || home_matches(&success.durable),
                        "partial native home {label}"
                    );
                    retain_delta(
                        &out.join(format!("{label}-recovered.delta")),
                        &base,
                        &target.durable,
                    );
                    let image = out.join("interruption-work.img");
                    fs::write(&image, &target.durable).unwrap();
                    run(
                        &tools[2],
                        &["-fn".into(), image.display().to_string()],
                        out,
                        receipt,
                        commands,
                        false,
                    );
                    let dump = out.join("interruption-payload.bin");
                    if dump.exists() {
                        fs::remove_file(&dump).unwrap();
                    }
                    // An unrelated, separately generated payload must survive every
                    // cut, including deletion of a different allocated inode.
                    run(
                        &tools[1],
                        &[
                            "-R".into(),
                            format!("dump {} {}", model.survivor, dump.display()),
                            image.display().to_string(),
                        ],
                        out,
                        receipt,
                        commands,
                        false,
                    );
                    assert_eq!(fs::read(&dump).unwrap(), expected);
                    let checked = session::Session::open(target, limits, &r).unwrap();
                    drop(checked);
                    assert_eq!(r.memory.used(), 0);
                    receipt.push_str(&format!("{}={label} old={old} recovered_sha256={:x} unchanged_payload_sha256={:x}\n", model.key, Sha256::digest(fs::read(&image).unwrap()), Sha256::digest(fs::read(&dump).unwrap())));
                }
            }
        }
    }
}

pub(super) fn indexed_operations(
    out: &Path,
    stem: &str,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
) {
    let image = out.join(format!("{stem}-htree-source.img"));
    fs::copy(out.join(format!("{stem}-namespace-0.img")), &image).unwrap();
    let empty = out.join("htree-empty.bin");
    fs::write(&empty, []).unwrap();
    let names: Vec<String> = (0..400)
        .map(|i| format!("entry{i:04}{}", "x".repeat(246)))
        .collect();
    assert!(names.iter().all(|name| name.len() == 255));
    let script = out.join("htree-debugfs.txt");
    let mut text = String::new();
    for name in &names {
        text.push_str(&format!("write {} /{name}\n", empty.display()));
    }
    fs::write(&script, text).unwrap();
    run(
        &tools[1],
        &[
            "-w".into(),
            "-f".into(),
            script.display().to_string(),
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
    let source = fs::read(&image).unwrap();
    fs::write(out.join(format!("{stem}-htree-before.img")), &source).unwrap();
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
        file_blocks: 1024,
        affected_blocks: 1024,
        affected_bytes: 4 << 20,
    };
    let planning = crate::fs_ext_edit::ExtEditLimits {
        audit: limits.audit,
        file_blocks: 1024,
        directory_entries: 2048,
        affected_bytes: 4 << 20,
        work: 1_000_000,
        undo: crate::fs_undo::UndoLimits {
            patches: 4096,
            body_bytes: 16 << 20,
        },
    };
    {
        let storage = FileStorage::open(&image).unwrap();
        let (decoder, proof) =
            super::super::super::ExtDecoder::open_native_clean(&storage, 18u128 << 64, &r).unwrap();
        let inode = decoder.inode(2, &r).unwrap();
        assert_ne!(super::super::super::u32le(&inode.raw, 32) & 0x1000, 0);
        let map = decoder.file_map(2, 256, &r, false).unwrap();
        let mut root = [0; 4096];
        decoder.read_map(&map, 0, &mut root[..1024], &r).unwrap();
        assert_eq!(
            root[30], 1,
            "native fixture must reach interior HTree level"
        );
        drop((decoder, proof, map));
    }
    let mut owner = session::Session::open(FileStorage::open(&image).unwrap(), limits, &r).unwrap();
    let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100640);
    let new_name = format!("new-owned{}", "q".repeat(246));
    assert_eq!(new_name.len(), 255);
    let steps = [
        session::Operation::Rename {
            source: &[],
            name: b"newfile",
            destination: &[],
            new_name: b"indexed-owned",
        },
        session::Operation::CreateFile {
            parent: &[],
            name: new_name.as_bytes(),
            metadata: &metadata,
            payload: &[],
        },
        session::Operation::Delete {
            parent: &[],
            name: new_name.as_bytes(),
            deletion_time: 1234567,
        },
    ];
    for (step, operation) in steps.into_iter().enumerate() {
        owner.operate(operation, planning, &r.cancellation).unwrap();
        let saved = out.join(format!("{stem}-htree-{step}.img"));
        fs::copy(&image, &saved).unwrap();
        run(
            &tools[2],
            &["-fn".into(), saved.display().to_string()],
            out,
            receipt,
            commands,
            false,
        );
        let dump = out.join(format!("{stem}-htree-{step}-payload.bin"));
        run(
            &tools[1],
            &[
                "-R".into(),
                format!("dump /indexed-owned {}", dump.display()),
                saved.display().to_string(),
            ],
            out,
            receipt,
            commands,
            false,
        );
        assert_eq!(
            fs::read(&dump).unwrap(),
            fs::read(out.join(format!("{stem}-namespace-expected.bin"))).unwrap()
        );
        let listing = run(
            &tools[1],
            &["-R".into(), "ls -l /".into(), saved.display().to_string()],
            out,
            receipt,
            commands,
            false,
        );
        let lines: Vec<&[u8]> = listing.split(|byte| *byte == b'\n').collect();
        for name in &names {
            let found = lines.iter().any(|line| {
                line.ends_with(name.as_bytes())
                    && line
                        .split(|b| b.is_ascii_whitespace())
                        .find(|x| !x.is_empty())
                        .is_some_and(|number| number != b"0")
            });
            assert!(found, "missing independent native name {name}");
        }
        receipt.push_str(&format!("validated_native_htree={stem} step={step} interior_levels=1 native_names=400 image_sha256={:x} payload_sha256={:x}\n",Sha256::digest(fs::read(saved).unwrap()),Sha256::digest(fs::read(dump).unwrap())));
    }
    drop(owner);
    assert_eq!(r.memory.used(), 0);
}

pub(super) fn shared_ea_hardlinks(
    out: &Path,
    stem: &str,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
) {
    let image = out.join(format!("{stem}-native-ea-source.img"));
    fs::copy(out.join(format!("{stem}-htree-2.img")), &image).unwrap();
    let original_stat = run(
        &tools[1],
        &[
            "-R".into(),
            "stat /renamed".into(),
            image.display().to_string(),
        ],
        out,
        receipt,
        commands,
        false,
    );
    let original = String::from_utf8(original_stat).unwrap();
    let line = original
        .lines()
        .find(|line| line.starts_with("File ACL:"))
        .unwrap();
    let physical: u32 = line.split_whitespace().nth(2).unwrap().parse().unwrap();
    assert_ne!(physical, 0);
    let script = out.join("native-ea-debugfs.txt");
    let text = format!(
        "ea_set /indexed-owned user.partmgr {}\nsif /indexed-owned file_acl {physical}\nfallocate /indexed-owned 130 150\nln /indexed-owned /native-alias\nsif /indexed-owned links_count 2\n",
        "z".repeat(600)
    );
    fs::write(&script, text).unwrap();
    run(
        &tools[1],
        &[
            "-w".into(),
            "-f".into(),
            script.display().to_string(),
            image.display().to_string(),
        ],
        out,
        receipt,
        commands,
        false,
    );
    // Fixture preparation deliberately lets the independent checker repair the
    // abandoned old EA allocation and materialize the shared block reference count.
    run(
        &tools[2],
        &["-fy".into(), image.display().to_string()],
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
    let source = fs::read(&image).unwrap();
    assert_eq!(
        u32::from_le_bytes(
            source[physical as usize * 1024 + 4..physical as usize * 1024 + 8]
                .try_into()
                .unwrap()
        ),
        2
    );
    fs::write(out.join(format!("{stem}-native-ea-before.img")), &source).unwrap();
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
        file_blocks: 1024,
        affected_blocks: 1024,
        affected_bytes: 4 << 20,
    };
    let planning = crate::fs_ext_edit::ExtEditLimits {
        audit: limits.audit,
        file_blocks: 1024,
        directory_entries: 2048,
        affected_bytes: 4 << 20,
        work: 1_000_000,
        undo: crate::fs_undo::UndoLimits {
            patches: 4096,
            body_bytes: 16 << 20,
        },
    };
    let mut owner = session::Session::open(FileStorage::open(&image).unwrap(), limits, &r).unwrap();
    for (step, name) in [b"indexed-owned".as_slice(), b"native-alias", b"renamed"]
        .into_iter()
        .enumerate()
    {
        owner
            .operate(
                session::Operation::Delete {
                    parent: &[],
                    name,
                    deletion_time: 1234567,
                },
                planning,
                &r.cancellation,
            )
            .unwrap();
        let saved = out.join(format!("{stem}-native-ea-{step}.img"));
        fs::copy(&image, &saved).unwrap();
        run(
            &tools[2],
            &["-fn".into(), saved.display().to_string()],
            out,
            receipt,
            commands,
            false,
        );
        let bytes = fs::read(&saved).unwrap();
        if step < 2 {
            let references = u32::from_le_bytes(
                bytes[physical as usize * 1024 + 4..physical as usize * 1024 + 8]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(references, if step == 0 { 2 } else { 1 });
            let ea = out.join(format!("{stem}-native-ea-{step}-value.bin"));
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
            assert_eq!(fs::read(ea).unwrap(), vec![b'z'; 600]);
        }
        if step == 0 {
            let dump = out.join(format!("{stem}-native-ea-alias.bin"));
            run(
                &tools[1],
                &[
                    "-R".into(),
                    format!("dump /native-alias {}", dump.display()),
                    saved.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            assert_eq!(
                fs::read(dump).unwrap(),
                fs::read(out.join(format!("{stem}-namespace-expected.bin"))).unwrap()
            );
            let stat = run(
                &tools[1],
                &[
                    "-R".into(),
                    "stat /native-alias".into(),
                    saved.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            assert!(String::from_utf8(stat).unwrap().contains("130-150"));
        } else {
            let output = run(
                &tools[1],
                &[
                    "-R".into(),
                    format!("testb {physical}"),
                    saved.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            let output = String::from_utf8(output).unwrap();
            if step == 1 {
                assert!(
                    !output.contains("not in use"),
                    "remaining EA owner lost its allocation: {output}"
                );
            } else if !output.contains("not in use") {
                // A released EA block may be reused by this transaction's rebuilt
                // directory; require independent native ownership, not a free bit.
                let owners = run(
                    &tools[1],
                    &[
                        "-R".into(),
                        format!("icheck {physical}"),
                        saved.display().to_string(),
                    ],
                    out,
                    receipt,
                    commands,
                    false,
                );
                let owners = String::from_utf8(owners).unwrap();
                assert!(
                    owners
                        .lines()
                        .any(|line| line.split_whitespace().collect::<Vec<_>>()
                            == [physical.to_string(), "2".to_string()]),
                    "released EA has unexpected owner: {owners}"
                );
                assert_ne!(
                    u32::from_le_bytes(
                        bytes[physical as usize * 1024..physical as usize * 1024 + 4]
                            .try_into()
                            .unwrap()
                    ),
                    0xea020000
                );
            }
        }
        receipt.push_str(&format!(
            "validated_native_shared_ea={stem} step={step} physical={physical} image_sha256={:x}\n",
            Sha256::digest(bytes)
        ));
    }
    drop(owner);
    assert_eq!(r.memory.used(), 0);
}
