//! Independently authored native uninitialized-inode bitmap materialization oracle.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

pub(super) fn operations(
    out: &Path,
    tools: &[PathBuf],
    receipt: &mut String,
    commands: &mut usize,
) {
    let stem = "native-uninitialized-inode";
    let image = out.join(format!("{stem}.img"));
    fs::File::create(&image).unwrap().set_len(16 << 20).unwrap();
    run(
        &tools[0],
        &[
            "-q".into(),
            "-F".into(),
            "-t".into(),
            "ext4".into(),
            "-b".into(),
            "1024".into(),
            "-I".into(),
            "256".into(),
            "-N".into(),
            "128".into(),
            image.display().to_string(),
        ],
        out,
        receipt,
        commands,
        false,
    );
    let initial = fs::read(&image).unwrap();
    assert_eq!(super::super::super::u32le(&initial, 1024), 128);
    assert_eq!(super::super::super::u32le(&initial, 1024 + 40), 64);
    assert_eq!(super::super::super::u16le(&initial, 1024 + 254), 64);
    assert_eq!(super::super::super::u16le(&initial, 2048 + 14), 52);
    assert_eq!(super::super::super::u16le(&initial, 2048 + 64 + 18), 5);
    let empty = out.join(format!("{stem}-empty.bin"));
    fs::write(&empty, []).unwrap();
    let script = out.join(format!("{stem}-debugfs.txt"));
    fs::write(
        &script,
        (0..52)
            .map(|n| format!("write {} /fill{n:04}\n", empty.display()))
            .collect::<String>(),
    )
    .unwrap();
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
        &["-fn".into(), image.display().to_string()],
        out,
        receipt,
        commands,
        false,
    );
    let before = fs::read(&image).unwrap();
    assert_eq!(super::super::super::u16le(&before, 2048 + 14), 0);
    assert_eq!(super::super::super::u16le(&before, 2048 + 64 + 14), 64);
    assert_eq!(super::super::super::u16le(&before, 2048 + 64 + 18), 5);
    fs::write(out.join(format!("{stem}-before.img")), &before).unwrap();
    let bitmap0 = super::super::super::u32le(&before, 2048 + 4) as usize * 1024;
    let bitmap1 = super::super::super::u32le(&before, 2048 + 64 + 4) as usize * 1024;
    let table0 = super::super::super::u32le(&before, 2048 + 8) as usize * 1024;
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
    let payload: Vec<u8> = (0..131089).map(|n| (n * 29 + n / 83) as u8).collect();
    let expected = out.join(format!("{stem}-expected.bin"));
    fs::write(&expected, &payload).unwrap();
    let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100640);
    let mut owner = session::Session::open(FileStorage::open(&image).unwrap(), limits, &r).unwrap();
    let path = [crate::fs_core::NativeName::Bytes(b"materialized".to_vec())];
    let prior = owner
        .file_at(
            &[crate::fs_core::NativeName::Bytes(b"fill0000".to_vec())],
            &r.cancellation,
        )
        .unwrap();
    owner
        .operate(
            session::Operation::CreateFile {
                parent: &[],
                name: b"materialized",
                metadata: &metadata,
                payload: &payload,
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    let handle = owner.file_at(&path, &r.cancellation).unwrap();
    assert_eq!(handle.inode_number(), 65);
    assert_eq!(
        handle.identity.generation,
        prior.identity.generation.checked_add(1).unwrap()
    );
    assert!(
        owner
            .read_at(&prior, 0, &mut [0; 1], &r.cancellation)
            .is_err()
    );
    let mut actual = vec![0; payload.len()];
    assert_eq!(
        owner
            .read_at(&handle, 0, &mut actual, &r.cancellation)
            .unwrap(),
        actual.len()
    );
    assert_eq!(actual, payload);
    for step in 0..2 {
        if step == 1 {
            owner
                .operate(
                    session::Operation::Delete {
                        parent: &[],
                        name: b"materialized",
                        deletion_time: 1234567,
                    },
                    planning,
                    &r.cancellation,
                )
                .unwrap();
            assert!(
                owner
                    .read_at(&handle, 0, &mut [0; 1], &r.cancellation)
                    .is_err()
            );
        }
        let after = fs::read(&image).unwrap();
        assert_eq!(
            &after[bitmap0..bitmap0 + 1024],
            &before[bitmap0..bitmap0 + 1024]
        );
        assert_eq!(
            &after[table0..table0 + 64 * 256],
            &before[table0..table0 + 64 * 256]
        );
        assert_eq!(super::super::super::u16le(&after, 2048 + 64 + 18), 4);
        assert_eq!(
            super::super::super::u16le(&after, 2048 + 64 + 14),
            if step == 0 { 63 } else { 64 }
        );
        assert_eq!(after[bitmap1], if step == 0 { 1 } else { 0 });
        assert!(after[bitmap1 + 1..bitmap1 + 8].iter().all(|v| *v == 0));
        assert!(after[bitmap1 + 8..bitmap1 + 1024].iter().all(|v| *v == 255));
        let saved = out.join(format!("{stem}-{step}.img"));
        fs::write(&saved, &after).unwrap();
        run(
            &tools[2],
            &["-fn".into(), saved.display().to_string()],
            out,
            receipt,
            commands,
            false,
        );
        let listing = run(
            &tools[1],
            &["-R".into(), "ls -l /".into(), saved.display().to_string()],
            out,
            receipt,
            commands,
            false,
        );
        let listing = String::from_utf8(listing).unwrap();
        for n in 0..52 {
            assert!(
                listing
                    .lines()
                    .any(|line| line.split_whitespace().last()
                        == Some(format!("fill{n:04}").as_str()))
            );
        }
        if step == 0 {
            let dump = out.join(format!("{stem}-payload.bin"));
            run(
                &tools[1],
                &[
                    "-R".into(),
                    format!("dump /materialized {}", dump.display()),
                    saved.display().to_string(),
                ],
                out,
                receipt,
                commands,
                false,
            );
            assert_eq!(fs::read(dump).unwrap(), payload);
        }
        receipt.push_str(&format!("validated_native_uninitialized_inode={stem} step={step} inode=65 image_sha256={:x} payload_sha256={:x}\n", Sha256::digest(after), Sha256::digest(&payload)));
    }
    drop(prior);
    drop(handle);
    drop(owner);
    assert_eq!(r.memory.used(), 0);
}
