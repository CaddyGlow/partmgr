//! Independently assembled checksum-profile legacy maps; no production fixture codec.
use super::*;
fn fixture_direct(extent_feature: bool) -> Vec<u8> {
    let mut bytes = fixture();
    let seed = crc(!0, &[0x39; 16]);
    if !extent_feature {
        le(&mut bytes, 1120, 0x82);
    }
    let at = 5 * 1024 + 10 * 256;
    le(&mut bytes, at + 4, 2500);
    le(&mut bytes, at + 32, 0);
    le(&mut bytes, at + 28, 6);
    bytes[at + 40..at + 100].fill(0);
    for (slot, physical) in [41, 42, 43].into_iter().enumerate() {
        le(&mut bytes, at + 40 + slot * 4, physical);
    }
    word(&mut bytes, at + 124, 0);
    word(&mut bytes, at + 130, 0);
    let checksum = crc(
        crc(crc(seed, &11u32.to_le_bytes()), &0u32.to_le_bytes()),
        &bytes[at..at + 256],
    );
    word(&mut bytes, at + 124, checksum as u16);
    word(&mut bytes, at + 130, (checksum >> 16) as u16);
    for physical in [44usize, 45] {
        let bit = physical - 1;
        bytes[3 * 1024 + bit / 8] &= !(1 << (bit % 8));
    }
    le(&mut bytes, 1036, 978);
    word(&mut bytes, 2060, 978);
    let checksum = crc(seed, &bytes[3 * 1024..3 * 1024 + 256]);
    word(&mut bytes, 2072, checksum as u16);
    word(&mut bytes, 2104, (checksum >> 16) as u16);
    word(&mut bytes, 2078, 0);
    let checksum = crc(crc(seed, &0u32.to_le_bytes()), &bytes[2048..2112]);
    word(&mut bytes, 2078, checksum as u16);
    let checksum = crc(!0, &bytes[1024..2044]);
    le(&mut bytes, 2044, checksum);
    bytes
}
fn limits() -> (session::Limits, ExtEditLimits) {
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 1_000_000,
            directory_blocks: 16,
            directory_entries: 64,
            findings: 8,
        },
        file_blocks: 512,
        affected_blocks: 512,
        affected_bytes: 2 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 512,
        directory_entries: 64,
        affected_bytes: 2 << 20,
        work: 1_000_000,
        undo: crate::fs_undo::UndoLimits {
            patches: 2048,
            body_bytes: 8 << 20,
        },
    };
    (limits, planning)
}
#[test]
fn checksum_indirect_extend_crosses_single_double_truncate_preserves_profile_and_refunds() {
    let (limits, planning) = limits();
    for extent_feature in [false, true] {
        let r = Resources {
            memory: Budget::new(128 << 20),
            cancellation: Cancellation::default(),
        };
        let bytes = fixture_direct(extent_feature);
        let storage = recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes.clone(),
            events: 0,
            cut: usize::MAX,
            immediate: true,
            failed_flush_persists: true,
            torn: false,
        };
        let mut owner = session::Session::open(storage, limits, &r).unwrap();
        let old = owner.file(11, &r.cancellation).unwrap();
        let mut expected = vec![0; 2500];
        assert_eq!(
            owner
                .read_at(&old, 0, &mut expected, &r.cancellation)
                .unwrap(),
            2500
        );
        let input = Input {
            identity: crate::fs_core::ObjectId {
                source: 999,
                generation: 0,
                native: vec![1],
            },
            bytes: (0..300000).map(|n| (n * 31 + n / 17) as u8).collect(),
        };
        expected.extend_from_slice(&input.bytes);
        owner
            .operate(
                session::Operation::Extend {
                    file: &old,
                    input: &input,
                },
                planning,
                &r.cancellation,
            )
            .unwrap();
        assert!(
            owner
                .read_at(&old, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        drop(old);
        let file = owner.file(11, &r.cancellation).unwrap();
        let mut actual = vec![0; expected.len()];
        assert_eq!(
            owner
                .read_at(&file, 0, &mut actual, &r.cancellation)
                .unwrap(),
            actual.len()
        );
        assert!(
            actual == expected,
            "first payload difference: {:?}, appended actual={:?} expected={:?}",
            actual.iter().zip(&expected).position(|(a, b)| a != b),
            &actual[2500..2510],
            &expected[2500..2510]
        );
        let (target, _) = owner.into_storage();
        drop(file);
        assert_eq!(r.memory.used(), 0);
        let at = 5 * 1024 + 10 * 256;
        assert_eq!(
            u32::from_le_bytes(target.durable[at + 32..at + 36].try_into().unwrap()),
            0
        );
        assert_ne!(
            u32::from_le_bytes(target.durable[at + 88..at + 92].try_into().unwrap()),
            0
        );
        assert_ne!(
            u32::from_le_bytes(target.durable[at + 92..at + 96].try_into().unwrap()),
            0
        );
        let mut inode = target.durable[at..at + 256].to_vec();
        let saved = u32::from(u16::from_le_bytes(inode[124..126].try_into().unwrap()))
            | (u32::from(u16::from_le_bytes(inode[130..132].try_into().unwrap())) << 16);
        inode[124..126].fill(0);
        inode[130..132].fill(0);
        assert_eq!(
            saved,
            crc(
                crc(
                    crc(crc(!0, &[0x39; 16]), &11u32.to_le_bytes()),
                    &0u32.to_le_bytes()
                ),
                &inode
            )
        );
        let mut owner = session::Session::open(target, limits, &r).unwrap();
        let file = owner.file(11, &r.cancellation).unwrap();
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
        drop(file);
        let file = owner.file(11, &r.cancellation).unwrap();
        let mut kept = [0; 513];
        assert_eq!(
            owner.read_at(&file, 0, &mut kept, &r.cancellation).unwrap(),
            513
        );
        assert_eq!(kept, expected[..513]);
        drop(file);
        let (target, _) = owner.into_storage();
        assert_eq!(r.memory.used(), 0);
        assert_eq!(&target.durable[at + 88..at + 100], &[0; 12]);
        let checked = session::Session::open(target, limits, &r).unwrap();
        drop(checked);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn checksum_without_extent_feature_create_move_and_delete_preserves_indirect_profile() {
    let (limits, planning) = limits();
    let r = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = fixture_direct(false);
    let target = recovery::tests::Fault {
        visible: bytes.clone(),
        durable: bytes,
        events: 0,
        cut: usize::MAX,
        immediate: true,
        failed_flush_persists: true,
        torn: false,
    };
    let mut owner = session::Session::open(target, limits, &r).unwrap();
    let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100640);
    let dir = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o40750);
    let payload: Vec<u8> = (0..20000).map(|n| (n * 7) as u8).collect();
    owner
        .operate(
            session::Operation::CreateFile {
                parent: &[],
                name: b"new-\xff",
                metadata: &metadata,
                payload: &payload,
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    owner
        .operate(
            session::Operation::CreateDirectory {
                parent: &[],
                name: b"dir",
                metadata: &dir,
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    let destination = [crate::fs_core::NativeName::Bytes(b"dir".to_vec())];
    owner
        .operate(
            session::Operation::Rename {
                source: &[],
                name: b"new-\xff",
                destination: &destination,
                new_name: b"moved",
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    let file = owner
        .file_at(
            &[
                destination[0].clone(),
                crate::fs_core::NativeName::Bytes(b"moved".to_vec()),
            ],
            &r.cancellation,
        )
        .unwrap();
    let number = file.inode_number();
    let mut actual = vec![0; payload.len()];
    assert_eq!(
        owner
            .read_at(&file, 0, &mut actual, &r.cancellation)
            .unwrap(),
        payload.len()
    );
    assert_eq!(actual, payload);
    drop(file);
    let (target, _) = owner.into_storage();
    assert_eq!(r.memory.used(), 0);
    let at = 5 * 1024 + (number as usize - 1) * 256;
    assert_eq!(&target.durable[at + 32..at + 36], &[0; 4]);
    let mut owner = session::Session::open(target, limits, &r).unwrap();
    owner
        .operate(
            session::Operation::Delete {
                parent: &destination,
                name: b"moved",
                deletion_time: 128,
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    owner
        .operate(
            session::Operation::Delete {
                parent: &[],
                name: b"dir",
                deletion_time: 128,
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    drop(owner);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn checksum_indirect_extend_truncate_restart_every_write_barrier_and_torn_cut() {
    let (limits, planning) = limits();
    let input = Input {
        identity: crate::fs_core::ObjectId {
            source: 998,
            generation: 0,
            native: vec![2],
        },
        bytes: (0..12000).map(|n| (n * 19 + n / 71) as u8).collect(),
    };
    for extent_feature in [false, true] {
        let bytes = fixture_direct(extent_feature);
        super::namespace_tests::independent_namespace_restart_matrix(
            bytes.clone(),
            limits,
            |owner, cancellation| {
                let file = owner.file(11, cancellation)?;
                owner.operate(
                    session::Operation::Extend {
                        file: &file,
                        input: &input,
                    },
                    planning,
                    cancellation,
                )
            },
        );
        let r = Resources {
            memory: Budget::new(128 << 20),
            cancellation: Cancellation::default(),
        };
        let target = recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes,
            events: 0,
            cut: usize::MAX,
            immediate: true,
            failed_flush_persists: true,
            torn: false,
        };
        let mut owner = session::Session::open(target, limits, &r).unwrap();
        let file = owner.file(11, &r.cancellation).unwrap();
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
        let (target, _) = owner.into_storage();
        assert_eq!(r.memory.used(), 0);
        super::namespace_tests::independent_namespace_restart_matrix(
            target.durable,
            limits,
            |owner, cancellation| {
                let file = owner.file(11, cancellation)?;
                owner.operate(
                    session::Operation::Truncate {
                        file: &file,
                        length: 513,
                    },
                    planning,
                    cancellation,
                )
            },
        );
    }
}
