//! Independent namespace fixtures and complete native lifecycle restart matrices.
use super::*;
#[cfg(not(feature = "std"))]
#[allow(unused_imports)] // Mirrors the allocation types supplied by the std prelude.
use crate::platform::prelude::*;

#[cfg(feature = "std")]
#[test]
fn modern_exact_native_rename_restart_every_write_barrier_and_torn_cut() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };

    {
        let make = |immediate, failed_flush_persists, torn, cut| recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes.clone(),
            events: 0,
            cut,
            immediate,
            failed_flush_persists,
            torn,
        };
        let perform = |owner: &mut session::Session<recovery::tests::Fault>| {
            owner.operate(
                session::Operation::Rename {
                    source: &[],
                    name: b"file",
                    destination: &[],
                    new_name: b"renamed-\xff",
                },
                planning,
                &r.cancellation,
            )
        };
        let mut success =
            session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
        let stale = success.file(11, &r.cancellation).unwrap();
        perform(&mut success).unwrap();
        assert!(
            success
                .read_at(&stale, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        drop(stale);
        let (success, _) = success.into_storage();
        let events = success.events;
        let mut independent = bytes.clone();
        independent[40 * 1024 + 30] = 9;
        independent[40 * 1024 + 32..41 * 1024 - 12].fill(0);
        independent[40 * 1024 + 32..40 * 1024 + 41].copy_from_slice(b"renamed-\xff");
        let seed = crc(
            crc(crc(!0, &[0x39; 16]), &2u32.to_le_bytes()),
            &0u32.to_le_bytes(),
        );
        let checksum = crc(seed, &independent[40 * 1024..40 * 1024 + 1012]);
        le(&mut independent, 40 * 1024 + 1020, checksum);
        assert_eq!(
            &success.durable[40 * 1024..41 * 1024],
            &independent[40 * 1024..41 * 1024]
        );
        assert_eq!(
            &success.durable[5 * 1024..37 * 1024],
            &bytes[5 * 1024..37 * 1024]
        );
        assert!(events > 24);
        for immediate in [false, true] {
            for failed_flush_persists in [false, true] {
                for torn in [false, true] {
                    for cut in 1..=events {
                        let mut owner = session::Session::open(
                            make(immediate, failed_flush_persists, torn, cut),
                            limits,
                            &r,
                        )
                        .unwrap();
                        assert!(perform(&mut owner).is_err());
                        let (mut target, _) = owner.into_storage();
                        assert_eq!(r.memory.used(), 0);
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
                        let same_home = |expected: &[u8]| {
                            target.durable[..100 * 1024] == expected[..100 * 1024]
                                && target.durable[1124 * 1024..] == expected[1124 * 1024..]
                        };
                        assert!(
                            same_home(&bytes) || same_home(&success.durable),
                            "partial modern rename home cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

fn directory_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    let seed = crc(!0, &[0x39; 16]);
    bytes[3 * 1024 + 45 / 8] |= 1 << (45 % 8);
    bytes[4 * 1024 + 11 / 8] |= 1 << (11 % 8);
    le(&mut bytes, 1024 + 12, 975);
    le(&mut bytes, 1024 + 16, 116);
    for (at, value) in [(12, 975), (14, 116), (16, 2), (28, 116)] {
        word(&mut bytes, 2048 + at, value);
    }
    let root = 5 * 1024 + 256;
    word(&mut bytes, root + 26, 3);
    let child = 5 * 1024 + 11 * 256;
    bytes[child..child + 256].fill(0);
    word(&mut bytes, child, 0o40755);
    le(&mut bytes, child + 4, 1024);
    word(&mut bytes, child + 26, 2);
    le(&mut bytes, child + 28, 2);
    le(&mut bytes, child + 40, 46);
    word(&mut bytes, child + 128, 32);
    for (number, at) in [(2u32, root), (12, child)] {
        word(&mut bytes, at + 124, 0);
        word(&mut bytes, at + 130, 0);
        let checksum = crc(
            crc(crc(seed, &number.to_le_bytes()), &0u32.to_le_bytes()),
            &bytes[at..at + 256],
        );
        word(&mut bytes, at + 124, checksum as u16);
        word(&mut bytes, at + 130, (checksum >> 16) as u16);
    }
    word(&mut bytes, 40 * 1024 + 28, 12);
    let at = 40 * 1024 + 36;
    le(&mut bytes, at, 12);
    word(&mut bytes, at + 4, 976);
    bytes[at + 6] = 3;
    bytes[at + 7] = 2;
    bytes[at + 8..at + 11].copy_from_slice(b"dir");
    let at = 46 * 1024;
    bytes[at..at + 1024].fill(0);
    le(&mut bytes, at, 12);
    word(&mut bytes, at + 4, 12);
    bytes[at + 6] = 1;
    bytes[at + 7] = 2;
    bytes[at + 8] = b'.';
    le(&mut bytes, at + 12, 2);
    word(&mut bytes, at + 16, 1000);
    bytes[at + 18] = 2;
    bytes[at + 19] = 2;
    bytes[at + 20..at + 22].copy_from_slice(b"..");
    word(&mut bytes, at + 1016, 12);
    bytes[at + 1019] = 0xde;
    for (number, physical) in [(2u32, 40usize), (12, 46)] {
        let at = physical * 1024;
        let checksum = crc(
            crc(crc(seed, &number.to_le_bytes()), &0u32.to_le_bytes()),
            &bytes[at..at + 1012],
        );
        le(&mut bytes, at + 1020, checksum);
    }
    for (field, high, physical, count) in [(24, 56, 3usize, 256usize), (26, 58, 4, 16)] {
        let checksum = crc(seed, &bytes[physical * 1024..physical * 1024 + count]);
        word(&mut bytes, 2048 + field, checksum as u16);
        word(&mut bytes, 2048 + high, (checksum >> 16) as u16);
    }
    word(&mut bytes, 2048 + 30, 0);
    let checksum = crc(crc(seed, &0u32.to_le_bytes()), &bytes[2048..2112]);
    word(&mut bytes, 2048 + 30, checksum as u16);
    let checksum = crc(!0, &bytes[1024..2044]);
    le(&mut bytes, 2044, checksum);
    bytes
}

fn full_directory_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    let root = 5 * 1024 + 256;
    le(&mut bytes, root + 32, 0x80000);
    bytes[root + 40..root + 100].fill(0);
    word(&mut bytes, root + 40, 0xf30a);
    word(&mut bytes, root + 42, 1);
    word(&mut bytes, root + 44, 4);
    word(&mut bytes, root + 56, 1);
    le(&mut bytes, root + 60, 40);
    word(&mut bytes, 40 * 1024 + 28, 12);
    let seed = crc(!0, &[0x39; 16]);
    for index in 0..3 {
        let number = 12 + index as u32;
        let at = 5 * 1024 + (number as usize - 1) * 256;
        bytes[at..at + 256].fill(0);
        word(&mut bytes, at, 0o100640);
        word(&mut bytes, at + 26, 1);
        le(&mut bytes, at + 32, 0x80000);
        word(&mut bytes, at + 40, 0xf30a);
        word(&mut bytes, at + 44, 4);
        word(&mut bytes, at + 128, 32);
        let checksum = crc(
            crc(crc(seed, &number.to_le_bytes()), &0u32.to_le_bytes()),
            &bytes[at..at + 256],
        );
        word(&mut bytes, at + 124, checksum as u16);
        word(&mut bytes, at + 130, (checksum >> 16) as u16);
        let bit = number as usize - 1;
        bytes[4 * 1024 + bit / 8] |= 1 << (bit % 8);
        let at = 40 * 1024 + 36 + index * 264;
        bytes[at..at + 264].fill(b'a' + index as u8);
        le(&mut bytes, at, number);
        word(&mut bytes, at + 4, if index == 2 { 448 } else { 264 });
        bytes[at + 6] = 255;
        bytes[at + 7] = 1;
    }
    word(&mut bytes, root + 124, 0);
    word(&mut bytes, root + 130, 0);
    let checksum = crc(
        crc(crc(seed, &2u32.to_le_bytes()), &0u32.to_le_bytes()),
        &bytes[root..root + 256],
    );
    word(&mut bytes, root + 124, checksum as u16);
    word(&mut bytes, root + 130, (checksum >> 16) as u16);
    let checksum = crc(
        crc(crc(seed, &2u32.to_le_bytes()), &0u32.to_le_bytes()),
        &bytes[40 * 1024..40 * 1024 + 1012],
    );
    le(&mut bytes, 40 * 1024 + 1020, checksum);
    le(&mut bytes, 1024 + 16, 114);
    word(&mut bytes, 2048 + 14, 114);
    word(&mut bytes, 2048 + 28, 114);
    let checksum = crc(seed, &bytes[4 * 1024..4 * 1024 + 16]);
    word(&mut bytes, 2048 + 26, checksum as u16);
    word(&mut bytes, 2048 + 58, (checksum >> 16) as u16);
    word(&mut bytes, 2048 + 30, 0);
    let checksum = crc(crc(seed, &0u32.to_le_bytes()), &bytes[2048..2112]);
    word(&mut bytes, 2048 + 30, checksum as u16);
    let checksum = crc(!0, &bytes[1024..2044]);
    le(&mut bytes, 2044, checksum);
    bytes
}

#[cfg(feature = "std")]
#[test]
fn modern_cross_directory_file_move_restart_every_write_barrier_and_torn_cut() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = directory_fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };

    {
        let make = |immediate, failed_flush_persists, torn, cut| recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes.clone(),
            events: 0,
            cut,
            immediate,
            failed_flush_persists,
            torn,
        };
        let perform = |owner: &mut session::Session<recovery::tests::Fault>| {
            owner.operate(
                session::Operation::Rename {
                    source: &[],
                    name: b"file",
                    destination: &[crate::fs_core::NativeName::Bytes(b"dir".to_vec())],
                    new_name: b"moved-\xff",
                },
                planning,
                &r.cancellation,
            )
        };
        let mut success =
            session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
        let stale = success.file(11, &r.cancellation).unwrap();
        perform(&mut success).unwrap();
        assert!(
            success
                .read_at(&stale, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        drop(stale);
        let (success, _) = success.into_storage();
        let events = success.events;
        let mut independent = bytes.clone();
        independent[40 * 1024 + 24..40 * 1024 + 28].fill(0);
        word(&mut independent, 46 * 1024 + 16, 12);
        let at = 46 * 1024 + 24;
        independent[at..47 * 1024 - 12].fill(0);
        le(&mut independent, at, 11);
        word(&mut independent, at + 4, 988);
        independent[at + 6] = 7;
        independent[at + 7] = 1;
        independent[at + 8..at + 15].copy_from_slice(b"moved-\xff");
        let seed = crc(!0, &[0x39; 16]);
        for (number, physical) in [(2u32, 40usize), (12, 46)] {
            let at = physical * 1024;
            let checksum = crc(
                crc(crc(seed, &number.to_le_bytes()), &0u32.to_le_bytes()),
                &independent[at..at + 1012],
            );
            le(&mut independent, at + 1020, checksum);
        }
        assert_eq!(
            &success.durable[40 * 1024..47 * 1024],
            &independent[40 * 1024..47 * 1024]
        );
        assert_eq!(
            &success.durable[5 * 1024..37 * 1024],
            &bytes[5 * 1024..37 * 1024]
        );
        assert!(events > 24);
        for immediate in [false, true] {
            for failed_flush_persists in [false, true] {
                for torn in [false, true] {
                    for cut in 1..=events {
                        let mut owner = session::Session::open(
                            make(immediate, failed_flush_persists, torn, cut),
                            limits,
                            &r,
                        )
                        .unwrap();
                        assert!(perform(&mut owner).is_err());
                        let (mut target, _) = owner.into_storage();
                        assert_eq!(r.memory.used(), 0);
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
                        let same_home = |expected: &[u8]| {
                            target.durable[..100 * 1024] == expected[..100 * 1024]
                                && target.durable[1124 * 1024..] == expected[1124 * 1024..]
                        };
                        assert!(
                            same_home(&bytes) || same_home(&success.durable),
                            "partial modern move home cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn modern_create_file_restart_every_write_barrier_and_torn_cut() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };

    {
        let make = |immediate, failed_flush_persists, torn, cut| recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes.clone(),
            events: 0,
            cut,
            immediate,
            failed_flush_persists,
            torn,
        };
        let payload: Vec<u8> = (0..4097).map(|n| (n * 17 + n / 23) as u8).collect();
        let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100640);
        let perform = |owner: &mut session::Session<recovery::tests::Fault>| {
            owner.operate(
                session::Operation::CreateFile {
                    parent: &[],
                    name: b"created-\xff",
                    metadata: &metadata,
                    payload: &payload,
                },
                planning,
                &r.cancellation,
            )
        };
        let mut success =
            session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
        let stale = success.file(11, &r.cancellation).unwrap();
        perform(&mut success).unwrap();
        assert!(
            success
                .read_at(&stale, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        drop(stale);
        let (success, _) = success.into_storage();
        let events = success.events;
        let at = 5 * 1024 + 11 * 256;
        let inode = &success.durable[at..at + 256];
        assert_eq!(u32::from_le_bytes(inode[4..8].try_into().unwrap()), 4097);
        assert_eq!(u16::from_le_bytes(inode[26..28].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(inode[28..32].try_into().unwrap()), 10);
        assert_eq!(u32::from_le_bytes(inode[100..104].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(inode[42..44].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(inode[60..64].try_into().unwrap()), 37);
        assert_eq!(u32::from_le_bytes(inode[72..76].try_into().unwrap()), 46);
        let mut checked = inode.to_vec();
        let low = u16::from_le_bytes(checked[124..126].try_into().unwrap());
        let high = u16::from_le_bytes(checked[130..132].try_into().unwrap());
        checked[124..126].fill(0);
        checked[130..132].fill(0);
        let checksum = crc(
            crc(
                crc(crc(!0, &[0x39; 16]), &12u32.to_le_bytes()),
                &1u32.to_le_bytes(),
            ),
            &checked,
        );
        assert_eq!(u32::from(low) | u32::from(high) << 16, checksum);
        let mut actual = Vec::new();
        for physical in [37usize, 38, 39, 46, 47] {
            actual.extend_from_slice(&success.durable[physical * 1024..(physical + 1) * 1024]);
        }
        assert_eq!(&actual[..payload.len()], &payload);
        assert!(actual[payload.len()..].iter().all(|b| *b == 0));
        assert_eq!(
            &success.durable[41 * 1024..46 * 1024],
            &bytes[41 * 1024..46 * 1024]
        );
        assert!(events > 24);
        for immediate in [false, true] {
            for failed_flush_persists in [false, true] {
                for torn in [false, true] {
                    for cut in 1..=events {
                        let mut owner = session::Session::open(
                            make(immediate, failed_flush_persists, torn, cut),
                            limits,
                            &r,
                        )
                        .unwrap();
                        assert!(perform(&mut owner).is_err());
                        let (mut target, _) = owner.into_storage();
                        assert_eq!(r.memory.used(), 0);
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
                        let same_home = |expected: &[u8]| {
                            target.durable[..100 * 1024] == expected[..100 * 1024]
                                && target.durable[1124 * 1024..] == expected[1124 * 1024..]
                        };
                        assert!(
                            same_home(&bytes) || same_home(&success.durable),
                            "partial modern create home cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn modern_create_empty_file_directory_growth_restart_every_write_barrier_and_torn_cut() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = full_directory_fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };

    {
        let make = |immediate, failed_flush_persists, torn, cut| recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes.clone(),
            events: 0,
            cut,
            immediate,
            failed_flush_persists,
            torn,
        };
        let payload = Vec::new();
        let mut name = vec![b'd'; 255];
        name[254] = 0xff;
        let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100640);
        let perform = |owner: &mut session::Session<recovery::tests::Fault>| {
            owner.operate(
                session::Operation::CreateFile {
                    parent: &[],
                    name: &name,
                    metadata: &metadata,
                    payload: &payload,
                },
                planning,
                &r.cancellation,
            )
        };
        let mut success =
            session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
        let stale = success.file(11, &r.cancellation).unwrap();
        perform(&mut success).unwrap();
        assert!(
            success
                .read_at(&stale, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        drop(stale);
        let (success, _) = success.into_storage();
        let events = success.events;
        let root = 5 * 1024 + 256;
        assert_eq!(
            u32::from_le_bytes(success.durable[root + 4..root + 8].try_into().unwrap()),
            2048
        );
        assert_eq!(
            u16::from_le_bytes(success.durable[root + 42..root + 44].try_into().unwrap()),
            2
        );
        assert_eq!(
            u32::from_le_bytes(success.durable[root + 72..root + 76].try_into().unwrap()),
            37
        );
        assert_eq!(
            &success.durable[40 * 1024..41 * 1024],
            &bytes[40 * 1024..41 * 1024]
        );
        let leaf = &success.durable[37 * 1024..38 * 1024];
        assert_eq!(u32::from_le_bytes(leaf[..4].try_into().unwrap()), 15);
        assert_eq!(&leaf[8..263], &name);
        assert_eq!(
            crc(
                crc(
                    crc(crc(!0, &[0x39; 16]), &2u32.to_le_bytes()),
                    &0u32.to_le_bytes()
                ),
                &leaf[..1012]
            ),
            u32::from_le_bytes(leaf[1020..].try_into().unwrap())
        );
        assert!(events > 24);
        for immediate in [false, true] {
            for failed_flush_persists in [false, true] {
                for torn in [false, true] {
                    for cut in 1..=events {
                        let mut owner = session::Session::open(
                            make(immediate, failed_flush_persists, torn, cut),
                            limits,
                            &r,
                        )
                        .unwrap();
                        assert!(perform(&mut owner).is_err());
                        let (mut target, _) = owner.into_storage();
                        assert_eq!(r.memory.used(), 0);
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
                        let same_home = |expected: &[u8]| {
                            target.durable[..100 * 1024] == expected[..100 * 1024]
                                && target.durable[1124 * 1024..] == expected[1124 * 1024..]
                        };
                        assert!(
                            same_home(&bytes) || same_home(&success.durable),
                            "partial modern directory growth home cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn modern_mkdir_with_parent_growth_restart_every_write_barrier_and_torn_cut() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = full_directory_fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };

    {
        let make = |immediate, failed_flush_persists, torn, cut| recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes.clone(),
            events: 0,
            cut,
            immediate,
            failed_flush_persists,
            torn,
        };
        let mut name = vec![b'd'; 255];
        name[254] = 0xff;
        let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o40750);
        let perform = |owner: &mut session::Session<recovery::tests::Fault>| {
            owner.operate(
                session::Operation::CreateDirectory {
                    parent: &[],
                    name: &name,
                    metadata: &metadata,
                },
                planning,
                &r.cancellation,
            )
        };
        let mut success =
            session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
        let stale = success.file(11, &r.cancellation).unwrap();
        perform(&mut success).unwrap();
        assert!(
            success
                .read_at(&stale, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        drop(stale);
        let (success, _) = success.into_storage();
        let events = success.events;
        let root = 5 * 1024 + 256;
        assert_eq!(
            u32::from_le_bytes(success.durable[root + 4..root + 8].try_into().unwrap()),
            2048
        );
        assert_eq!(
            u16::from_le_bytes(success.durable[root + 42..root + 44].try_into().unwrap()),
            2
        );
        assert_eq!(
            u32::from_le_bytes(success.durable[root + 72..root + 76].try_into().unwrap()),
            38
        );
        assert_eq!(
            &success.durable[40 * 1024..41 * 1024],
            &bytes[40 * 1024..41 * 1024]
        );
        let leaf = &success.durable[38 * 1024..39 * 1024];
        assert_eq!(u32::from_le_bytes(leaf[..4].try_into().unwrap()), 15);
        assert_eq!(&leaf[8..263], &name);
        assert_eq!(
            crc(
                crc(
                    crc(crc(!0, &[0x39; 16]), &2u32.to_le_bytes()),
                    &0u32.to_le_bytes()
                ),
                &leaf[..1012]
            ),
            u32::from_le_bytes(leaf[1020..].try_into().unwrap())
        );
        assert_eq!(
            u16::from_le_bytes(success.durable[root + 26..root + 28].try_into().unwrap()),
            3
        );
        let child = &success.durable[37 * 1024..38 * 1024];
        assert_eq!(u32::from_le_bytes(child[..4].try_into().unwrap()), 15);
        assert_eq!(u32::from_le_bytes(child[12..16].try_into().unwrap()), 2);
        assert_eq!(
            crc(
                crc(
                    crc(crc(!0, &[0x39; 16]), &15u32.to_le_bytes()),
                    &1u32.to_le_bytes()
                ),
                &child[..1012]
            ),
            u32::from_le_bytes(child[1020..].try_into().unwrap())
        );
        assert!(events > 24);
        for immediate in [false, true] {
            for failed_flush_persists in [false, true] {
                for torn in [false, true] {
                    for cut in 1..=events {
                        let mut owner = session::Session::open(
                            make(immediate, failed_flush_persists, torn, cut),
                            limits,
                            &r,
                        )
                        .unwrap();
                        assert!(perform(&mut owner).is_err());
                        let (mut target, _) = owner.into_storage();
                        assert_eq!(r.memory.used(), 0);
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
                        let same_home = |expected: &[u8]| {
                            target.durable[..100 * 1024] == expected[..100 * 1024]
                                && target.durable[1124 * 1024..] == expected[1124 * 1024..]
                        };
                        assert!(
                            same_home(&bytes) || same_home(&success.durable),
                            "partial modern directory growth home cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn modern_delete_file_restart_every_write_barrier_and_torn_cut() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };

    {
        let make = |immediate, failed_flush_persists, torn, cut| recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes.clone(),
            events: 0,
            cut,
            immediate,
            failed_flush_persists,
            torn,
        };
        let perform = |owner: &mut session::Session<recovery::tests::Fault>| {
            owner.operate(
                session::Operation::Delete {
                    parent: &[],
                    name: b"file",
                    deletion_time: 128,
                },
                planning,
                &r.cancellation,
            )
        };
        let mut success =
            session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
        let stale = success.file(11, &r.cancellation).unwrap();
        perform(&mut success).unwrap();
        assert!(
            success
                .read_at(&stale, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        drop(stale);
        let (success, _) = success.into_storage();
        let events = success.events;
        let at = 5 * 1024 + 10 * 256;
        let inode = &success.durable[at..at + 256];
        assert_eq!(u16::from_le_bytes(inode[26..28].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(inode[20..24].try_into().unwrap()), 128);
        assert!(inode[40..100].iter().all(|b| *b == 0));
        assert_eq!(
            u32::from_le_bytes(success.durable[1036..1040].try_into().unwrap()),
            981
        );
        assert_eq!(
            u32::from_le_bytes(success.durable[1040..1044].try_into().unwrap()),
            118
        );
        assert_eq!(
            &success.durable[41 * 1024..46 * 1024],
            &bytes[41 * 1024..46 * 1024]
        );
        assert!(events > 24);
        for immediate in [false, true] {
            for failed_flush_persists in [false, true] {
                for torn in [false, true] {
                    for cut in 1..=events {
                        let mut owner = session::Session::open(
                            make(immediate, failed_flush_persists, torn, cut),
                            limits,
                            &r,
                        )
                        .unwrap();
                        assert!(perform(&mut owner).is_err());
                        let (mut target, _) = owner.into_storage();
                        assert_eq!(r.memory.used(), 0);
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
                        let same_home = |expected: &[u8]| {
                            target.durable[..100 * 1024] == expected[..100 * 1024]
                                && target.durable[1124 * 1024..] == expected[1124 * 1024..]
                        };
                        assert!(
                            same_home(&bytes) || same_home(&success.durable),
                            "partial modern delete home cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn modern_delete_empty_directory_restart_every_write_barrier_and_torn_cut() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let mut bytes = directory_fixture();
    let at = 5 * 1024 + 11 * 256;
    le(&mut bytes, at + 32, 0x80000);
    bytes[at + 40..at + 100].fill(0);
    word(&mut bytes, at + 40, 0xf30a);
    word(&mut bytes, at + 42, 1);
    word(&mut bytes, at + 44, 4);
    word(&mut bytes, at + 56, 1);
    le(&mut bytes, at + 60, 46);
    word(&mut bytes, at + 124, 0);
    word(&mut bytes, at + 130, 0);
    let checksum = crc(
        crc(
            crc(crc(!0, &[0x39; 16]), &12u32.to_le_bytes()),
            &0u32.to_le_bytes(),
        ),
        &bytes[at..at + 256],
    );
    word(&mut bytes, at + 124, checksum as u16);
    word(&mut bytes, at + 130, (checksum >> 16) as u16);
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };

    {
        let make = |immediate, failed_flush_persists, torn, cut| recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes.clone(),
            events: 0,
            cut,
            immediate,
            failed_flush_persists,
            torn,
        };
        let perform = |owner: &mut session::Session<recovery::tests::Fault>| {
            owner.operate(
                session::Operation::Delete {
                    parent: &[],
                    name: b"dir",
                    deletion_time: 128,
                },
                planning,
                &r.cancellation,
            )
        };
        let mut success =
            session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
        let stale = success.file(11, &r.cancellation).unwrap();
        perform(&mut success).unwrap();
        assert!(
            success
                .read_at(&stale, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        drop(stale);
        let (success, _) = success.into_storage();
        let events = success.events;
        let at = 5 * 1024 + 11 * 256;
        let inode = &success.durable[at..at + 256];
        assert_eq!(u16::from_le_bytes(inode[26..28].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(inode[20..24].try_into().unwrap()), 128);
        assert!(inode[40..100].iter().all(|b| *b == 0));
        assert_eq!(
            u32::from_le_bytes(success.durable[1036..1040].try_into().unwrap()),
            976
        );
        assert_eq!(
            u32::from_le_bytes(success.durable[1040..1044].try_into().unwrap()),
            117
        );
        assert_eq!(
            &success.durable[41 * 1024..46 * 1024],
            &bytes[41 * 1024..46 * 1024]
        );
        assert!(events > 24);
        for immediate in [false, true] {
            for failed_flush_persists in [false, true] {
                for torn in [false, true] {
                    for cut in 1..=events {
                        let mut owner = session::Session::open(
                            make(immediate, failed_flush_persists, torn, cut),
                            limits,
                            &r,
                        )
                        .unwrap();
                        assert!(perform(&mut owner).is_err());
                        let (mut target, _) = owner.into_storage();
                        assert_eq!(r.memory.used(), 0);
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
                        let same_home = |expected: &[u8]| {
                            target.durable[..100 * 1024] == expected[..100 * 1024]
                                && target.durable[1124 * 1024..] == expected[1124 * 1024..]
                        };
                        assert!(
                            same_home(&bytes) || same_home(&success.durable),
                            "partial modern rmdir home cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

fn two_directories_fixture() -> Vec<u8> {
    let mut bytes = directory_fixture();
    let root = 5 * 1024 + 256;
    word(&mut bytes, root + 26, 4);
    let child = 5 * 1024 + 12 * 256;
    let original = bytes[5 * 1024 + 11 * 256..5 * 1024 + 12 * 256].to_vec();
    bytes[child..child + 256].copy_from_slice(&original);
    le(&mut bytes, child + 40, 47);
    word(&mut bytes, child + 124, 0);
    word(&mut bytes, child + 130, 0);
    let seed = crc(!0, &[0x39; 16]);
    for (number, at) in [(2u32, root), (13, child)] {
        word(&mut bytes, at + 124, 0);
        word(&mut bytes, at + 130, 0);
        let checksum = crc(
            crc(crc(seed, &number.to_le_bytes()), &0u32.to_le_bytes()),
            &bytes[at..at + 256],
        );
        word(&mut bytes, at + 124, checksum as u16);
        word(&mut bytes, at + 130, (checksum >> 16) as u16);
    }
    let old = bytes[46 * 1024..47 * 1024].to_vec();
    bytes[47 * 1024..48 * 1024].copy_from_slice(&old);
    le(&mut bytes, 47 * 1024, 13);
    let checksum = crc(
        crc(crc(seed, &13u32.to_le_bytes()), &0u32.to_le_bytes()),
        &bytes[47 * 1024..47 * 1024 + 1012],
    );
    le(&mut bytes, 47 * 1024 + 1020, checksum);
    word(&mut bytes, 40 * 1024 + 40, 12);
    let at = 40 * 1024 + 48;
    le(&mut bytes, at, 13);
    word(&mut bytes, at + 4, 964);
    bytes[at + 6] = 5;
    bytes[at + 7] = 2;
    bytes[at + 8..at + 13].copy_from_slice(b"other");
    let checksum = crc(
        crc(crc(seed, &2u32.to_le_bytes()), &0u32.to_le_bytes()),
        &bytes[40 * 1024..40 * 1024 + 1012],
    );
    le(&mut bytes, 40 * 1024 + 1020, checksum);
    bytes[3 * 1024 + 46 / 8] |= 1 << (46 % 8);
    bytes[4 * 1024 + 12 / 8] |= 1 << (12 % 8);
    le(&mut bytes, 1024 + 12, 974);
    le(&mut bytes, 1024 + 16, 115);
    for (at, value) in [(12, 974), (14, 115), (16, 3), (28, 115)] {
        word(&mut bytes, 2048 + at, value);
    }
    for (lo, hi, physical, count) in [(24, 56, 3usize, 256usize), (26, 58, 4, 16)] {
        let checksum = crc(seed, &bytes[physical * 1024..physical * 1024 + count]);
        word(&mut bytes, 2048 + lo, checksum as u16);
        word(&mut bytes, 2048 + hi, (checksum >> 16) as u16);
    }
    word(&mut bytes, 2048 + 30, 0);
    let checksum = crc(crc(seed, &0u32.to_le_bytes()), &bytes[2048..2112]);
    word(&mut bytes, 2048 + 30, checksum as u16);
    let checksum = crc(!0, &bytes[1024..2044]);
    le(&mut bytes, 2044, checksum);
    bytes
}

#[cfg(feature = "std")]
#[test]
fn modern_cross_directory_directory_move_restart_every_write_barrier_and_torn_cut() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = two_directories_fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };

    {
        let make = |immediate, failed_flush_persists, torn, cut| recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes.clone(),
            events: 0,
            cut,
            immediate,
            failed_flush_persists,
            torn,
        };
        let perform = |owner: &mut session::Session<recovery::tests::Fault>| {
            owner.operate(
                session::Operation::Rename {
                    source: &[],
                    name: b"dir",
                    destination: &[crate::fs_core::NativeName::Bytes(b"other".to_vec())],
                    new_name: b"moved-\xff",
                },
                planning,
                &r.cancellation,
            )
        };
        let mut success =
            session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
        let stale = success.file(11, &r.cancellation).unwrap();
        perform(&mut success).unwrap();
        assert!(
            success
                .read_at(&stale, 0, &mut [0; 1], &r.cancellation)
                .is_err()
        );
        drop(stale);
        let (success, _) = success.into_storage();
        let events = success.events;
        assert_eq!(
            u32::from_le_bytes(
                success.durable[46 * 1024 + 12..46 * 1024 + 16]
                    .try_into()
                    .unwrap()
            ),
            13
        );
        for (number, expected) in [(2u32, 3u16), (12, 2), (13, 3)] {
            let at = 5 * 1024 + (number as usize - 1) * 256;
            assert_eq!(
                u16::from_le_bytes(success.durable[at + 26..at + 28].try_into().unwrap()),
                expected
            );
        }
        assert_eq!(
            &success.durable[41 * 1024..46 * 1024],
            &bytes[41 * 1024..46 * 1024]
        );
        assert!(events > 24);
        for immediate in [false, true] {
            for failed_flush_persists in [false, true] {
                for torn in [false, true] {
                    for cut in 1..=events {
                        let mut owner = session::Session::open(
                            make(immediate, failed_flush_persists, torn, cut),
                            limits,
                            &r,
                        )
                        .unwrap();
                        assert!(perform(&mut owner).is_err());
                        let (mut target, _) = owner.into_storage();
                        assert_eq!(r.memory.used(), 0);
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
                        let same_home = |expected: &[u8]| {
                            target.durable[..100 * 1024] == expected[..100 * 1024]
                                && target.durable[1124 * 1024..] == expected[1124 * 1024..]
                        };
                        assert!(
                            same_home(&bytes) || same_home(&success.durable),
                            "partial modern moved-directory home cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}

fn shared_ea_hardlink_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    let compat = u32::from_le_bytes(bytes[1116..1120].try_into().unwrap());
    le(&mut bytes, 1116, compat | 8);
    let seed = crc(!0, &[0x39; 16]);
    let first = 5 * 1024 + 10 * 256;
    word(&mut bytes, first + 26, 2);
    le(&mut bytes, first + 28, 12);
    le(&mut bytes, first + 104, 46);
    let second = 5 * 1024 + 11 * 256;
    bytes[second..second + 256].fill(0);
    word(&mut bytes, second, 0o100640);
    word(&mut bytes, second + 26, 1);
    le(&mut bytes, second + 28, 2);
    le(&mut bytes, second + 32, 0x80000);
    word(&mut bytes, second + 40, 0xf30a);
    word(&mut bytes, second + 44, 4);
    le(&mut bytes, second + 104, 46);
    word(&mut bytes, second + 128, 32);
    for (number, at) in [(11u32, first), (12, second)] {
        word(&mut bytes, at + 124, 0);
        word(&mut bytes, at + 130, 0);
        let checksum = crc(
            crc(crc(seed, &number.to_le_bytes()), &0u32.to_le_bytes()),
            &bytes[at..at + 256],
        );
        word(&mut bytes, at + 124, checksum as u16);
        word(&mut bytes, at + 130, (checksum >> 16) as u16);
    }
    let at = 46 * 1024;
    bytes[at..at + 1024].fill(0);
    le(&mut bytes, at, 0xea020000);
    le(&mut bytes, at + 4, 2);
    le(&mut bytes, at + 8, 1);
    bytes[at + 32] = 4;
    bytes[at + 33] = 1;
    word(&mut bytes, at + 34, 1016);
    le(&mut bytes, at + 40, 5);
    bytes[at + 48..at + 52].copy_from_slice(b"test");
    bytes[at + 1016..at + 1021].copy_from_slice(b"value");
    let checksum = crc(crc(seed, &46u64.to_le_bytes()), &bytes[at..at + 1024]);
    le(&mut bytes, at + 16, checksum);
    word(&mut bytes, 40 * 1024 + 28, 12);
    for (relative, number, length, name) in [
        (36, 11, 16, b"alias".as_slice()),
        (52, 12, 960, b"mate".as_slice()),
    ] {
        let at = 40 * 1024 + relative;
        le(&mut bytes, at, number);
        word(&mut bytes, at + 4, length);
        bytes[at + 6] = name.len() as u8;
        bytes[at + 7] = 1;
        bytes[at + 8..at + 8 + name.len()].copy_from_slice(name);
    }
    let checksum = crc(
        crc(crc(seed, &2u32.to_le_bytes()), &0u32.to_le_bytes()),
        &bytes[40 * 1024..40 * 1024 + 1012],
    );
    le(&mut bytes, 40 * 1024 + 1020, checksum);
    bytes[3 * 1024 + 45 / 8] |= 1 << (45 % 8);
    bytes[4 * 1024 + 11 / 8] |= 1 << (11 % 8);
    le(&mut bytes, 1024 + 12, 975);
    le(&mut bytes, 1024 + 16, 116);
    for (at, value) in [(12, 975), (14, 116), (28, 116)] {
        word(&mut bytes, 2048 + at, value);
    }
    for (lo, hi, physical, count) in [(24, 56, 3usize, 256usize), (26, 58, 4, 16)] {
        let checksum = crc(seed, &bytes[physical * 1024..physical * 1024 + count]);
        word(&mut bytes, 2048 + lo, checksum as u16);
        word(&mut bytes, 2048 + hi, (checksum >> 16) as u16);
    }
    word(&mut bytes, 2048 + 30, 0);
    let checksum = crc(crc(seed, &0u32.to_le_bytes()), &bytes[2048..2112]);
    word(&mut bytes, 2048 + 30, checksum as u16);
    let checksum = crc(!0, &bytes[1024..2044]);
    le(&mut bytes, 2044, checksum);
    bytes
}

#[cfg(feature = "std")]
#[test]
fn independent_hardlink_shared_ea_lifetime_exact_reference_counts_and_refunds() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = shared_ea_hardlink_fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };
    let target = recovery::tests::Fault {
        visible: bytes.clone(),
        durable: bytes.clone(),
        events: 0,
        cut: usize::MAX,
        immediate: true,
        failed_flush_persists: true,
        torn: false,
    };
    let mut owner = session::Session::open(target, limits, &r).unwrap();
    for (step, name) in [b"file".as_slice(), b"alias", b"mate"]
        .into_iter()
        .enumerate()
    {
        owner
            .operate(
                session::Operation::Delete {
                    parent: &[],
                    name,
                    deletion_time: 128,
                },
                planning,
                &r.cancellation,
            )
            .unwrap();
        let (target, _) = owner.into_storage();
        if step == 0 {
            assert_eq!(
                &target.durable[46 * 1024..47 * 1024],
                &bytes[46 * 1024..47 * 1024]
            );
            assert_eq!(
                &target.durable[3 * 1024..5 * 1024],
                &bytes[3 * 1024..5 * 1024]
            );
        } else if step == 1 {
            let block = &target.durable[46 * 1024..47 * 1024];
            assert_eq!(u32::from_le_bytes(block[4..8].try_into().unwrap()), 1);
            assert_eq!(&block[1016..1021], b"value");
            let mut zeroed = block.to_vec();
            zeroed[16..20].fill(0);
            assert_eq!(
                crc(crc(crc(!0, &[0x39; 16]), &46u64.to_le_bytes()), &zeroed),
                u32::from_le_bytes(block[16..20].try_into().unwrap())
            );
            assert_ne!(target.durable[3 * 1024 + 45 / 8] & (1 << (45 % 8)), 0);
        } else {
            assert_eq!(target.durable[3 * 1024 + 45 / 8] & (1 << (45 % 8)), 0);
        }
        assert_eq!(
            &target.durable[41 * 1024..46 * 1024],
            &bytes[41 * 1024..46 * 1024]
        );
        assert_eq!(r.memory.used(), 0);
        owner = session::Session::open(target, limits, &r).unwrap();
    }
    drop(owner);
    assert_eq!(r.memory.used(), 0);
}

#[cfg(feature = "std")]
#[test]
fn independent_shared_ea_unlink_restart_every_write_barrier_and_torn_cut() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let mut bytes = shared_ea_hardlink_fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };

    for name in [b"file".as_slice(), b"alias", b"mate"] {
        let make = |immediate, failed_flush_persists, torn, cut| recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes.clone(),
            events: 0,
            cut,
            immediate,
            failed_flush_persists,
            torn,
        };
        let perform = |owner: &mut session::Session<recovery::tests::Fault>| {
            owner.operate(
                session::Operation::Delete {
                    parent: &[],
                    name,
                    deletion_time: 128,
                },
                planning,
                &r.cancellation,
            )
        };
        let mut owner =
            session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
        perform(&mut owner).unwrap();
        let (success, _) = owner.into_storage();
        assert_eq!(r.memory.used(), 0);
        for immediate in [false, true] {
            for failed_flush_persists in [false, true] {
                for torn in [false, true] {
                    for cut in 1..=success.events {
                        let mut owner = session::Session::open(
                            make(immediate, failed_flush_persists, torn, cut),
                            limits,
                            &r,
                        )
                        .unwrap();
                        assert!(perform(&mut owner).is_err());
                        let (mut target, _) = owner.into_storage();
                        assert_eq!(r.memory.used(), 0);
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
                            target.durable[..100 * 1024] == expected[..100 * 1024]
                                && target.durable[1124 * 1024..] == expected[1124 * 1024..]
                        };
                        assert!(
                            home_matches(&bytes) || home_matches(&success.durable),
                            "shared EA unlink partial home name={name:?} cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        let checked = session::Session::open(target, limits, &r).unwrap();
                        drop(checked);
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
        bytes = success.durable;
    }
}

fn uninitialized_inode_group_fixture() -> Vec<u8> {
    let mut bytes = uninitialized_second_group_fixture();
    let seed = crc(!0, &[0x39; 16]);
    for number in 12u32..=128 {
        let at = 5 * 1024 + (number as usize - 1) * 256;
        bytes[at..at + 256].fill(0);
        word(&mut bytes, at, 0o100644);
        word(&mut bytes, at + 26, 1);
        le(&mut bytes, at + 32, 0x80000);
        word(&mut bytes, at + 40, 0xf30a);
        word(&mut bytes, at + 44, 4);
        word(&mut bytes, at + 128, 32);
        let checksum = crc(
            crc(crc(seed, &number.to_le_bytes()), &0u32.to_le_bytes()),
            &bytes[at..at + 256],
        );
        word(&mut bytes, at + 124, checksum as u16);
        word(&mut bytes, at + 130, (checksum >> 16) as u16);
    }
    let mut entries = vec![
        (2u32, 2u8, b".".to_vec()),
        (2, 2, b"..".to_vec()),
        (11, 1, b"file".to_vec()),
    ];
    for number in 12u32..=128 {
        entries.push((number, 1, format!("i{number:03}").into_bytes()));
    }
    let mut cursor = 0;
    for physical in [40usize, 46] {
        let start = physical * 1024;
        bytes[start..start + 1024].fill(0);
        let mut at = 0;
        while cursor < entries.len() {
            let (number, kind, name) = &entries[cursor];
            let used = (8 + name.len()).next_multiple_of(4);
            if at + used > 1012 {
                break;
            }
            le(&mut bytes, start + at, *number);
            word(&mut bytes, start + at + 4, used as u16);
            bytes[start + at + 6] = name.len() as u8;
            bytes[start + at + 7] = *kind;
            bytes[start + at + 8..start + at + 8 + name.len()].copy_from_slice(name);
            cursor += 1;
            if cursor == entries.len()
                || at + used + (8 + entries[cursor].2.len()).next_multiple_of(4) > 1012
            {
                word(&mut bytes, start + at + 4, (1012 - at) as u16);
                break;
            }
            at += used;
        }
        word(&mut bytes, start + 1016, 12);
        bytes[start + 1019] = 0xde;
        let checksum = crc(
            crc(crc(seed, &2u32.to_le_bytes()), &0u32.to_le_bytes()),
            &bytes[start..start + 1012],
        );
        le(&mut bytes, start + 1020, checksum);
    }
    assert_eq!(cursor, entries.len());
    let root = 5 * 1024 + 256;
    bytes[root + 40..root + 100].fill(0);
    le(&mut bytes, root + 32, 0x80000);
    word(&mut bytes, root + 40, 0xf30a);
    word(&mut bytes, root + 44, 4);
    word(&mut bytes, root + 56, 1);
    le(&mut bytes, root + 60, 40);

    le(&mut bytes, root + 4, 2048);
    le(&mut bytes, root + 28, 4);
    word(&mut bytes, root + 42, 2);
    le(&mut bytes, root + 64, 1);
    word(&mut bytes, root + 68, 1);
    le(&mut bytes, root + 72, 46);
    word(&mut bytes, root + 124, 0);
    word(&mut bytes, root + 130, 0);
    let checksum = crc(
        crc(crc(seed, &2u32.to_le_bytes()), &0u32.to_le_bytes()),
        &bytes[root..root + 256],
    );
    word(&mut bytes, root + 124, checksum as u16);
    word(&mut bytes, root + 130, (checksum >> 16) as u16);
    bytes[4 * 1024..4 * 1024 + 16].fill(0xff);
    bytes[3 * 1024 + 45 / 8] |= 1 << (45 % 8);
    le(&mut bytes, 1024 + 12, 2987);
    le(&mut bytes, 1024 + 16, 128);
    word(&mut bytes, 2048 + 12, 976);
    word(&mut bytes, 2048 + 14, 0);
    word(&mut bytes, 2048 + 28, 0);
    for (lo, hi, physical, count) in [(24, 56, 3usize, 256usize), (26, 58, 4, 16)] {
        let checksum = crc(seed, &bytes[physical * 1024..physical * 1024 + count]);
        word(&mut bytes, 2048 + lo, checksum as u16);
        word(&mut bytes, 2048 + hi, (checksum >> 16) as u16);
    }
    word(&mut bytes, 2048 + 30, 0);
    let checksum = crc(crc(seed, &0u32.to_le_bytes()), &bytes[2048..2112]);
    word(&mut bytes, 2048 + 30, checksum as u16);
    let checksum = crc(!0, &bytes[1024..2044]);
    le(&mut bytes, 2044, checksum);
    bytes
}

#[cfg(feature = "std")]
#[test]
fn independent_uninitialized_inode_group_create_preserves_opaque_block_map_and_refunds() {
    let r = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = uninitialized_inode_group_fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 4096,
            inodes: 256,
            work: 4_000_000,
            directory_blocks: 8,
            directory_entries: 256,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 256,
        affected_bytes: 1 << 20,
        work: 4_000_000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };
    let target = recovery::tests::Fault {
        visible: bytes.clone(),
        durable: bytes.clone(),
        events: 0,
        cut: usize::MAX,
        immediate: true,
        failed_flush_persists: true,
        torn: false,
    };
    {
        let (decoder, proof) =
            super::super::super::super::ExtDecoder::open_native_clean(&target, 18u128 << 64, &r)
                .unwrap();
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits.audit, &r).unwrap();
        assert!(
            audit.is_clean(),
            "independent uninitialized inode fixture: {:?}",
            audit.findings()
        );
        drop((decoder, proof, audit));
    }
    let mut owner = session::Session::open(target, limits, &r).unwrap();
    let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100640);
    owner
        .operate(
            session::Operation::CreateFile {
                parent: &[],
                name: b"new-\xff",
                metadata: &metadata,
                payload: &[],
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    let handle = owner
        .file_at(
            &[crate::fs_core::NativeName::Bytes(b"new-\xff".to_vec())],
            &r.cancellation,
        )
        .unwrap();
    assert_eq!(handle.inode_number(), 129);
    drop(handle);
    let (target, _) = owner.into_storage();
    assert_eq!(r.memory.used(), 0);
    assert_eq!(
        &target.durable[2051 * 1024..2052 * 1024],
        &bytes[2051 * 1024..2052 * 1024]
    );
    assert_eq!(
        u16::from_le_bytes(target.durable[2112 + 18..2112 + 20].try_into().unwrap()),
        6
    );
    assert_eq!(target.durable[2052 * 1024] & 1, 1);
    assert_eq!(
        u32::from_le_bytes(target.durable[1040..1044].try_into().unwrap()),
        127
    );
    assert_eq!(&target.durable[1036..1040], &bytes[1036..1040]);
    assert_eq!(
        &target.durable[2112 + 24..2112 + 26],
        &bytes[2112 + 24..2112 + 26]
    );
    assert_eq!(
        &target.durable[2112 + 56..2112 + 58],
        &bytes[2112 + 56..2112 + 58]
    );
    let checked = session::Session::open(target, limits, &r).unwrap();
    drop(checked);
    assert_eq!(r.memory.used(), 0);
}

fn indexed_namespace_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    let seed = crc(!0, &[0x39; 16]);
    le(&mut bytes, 1024 + 352, 1);
    let compat = u32::from_le_bytes(bytes[1116..1120].try_into().unwrap());
    le(&mut bytes, 1116, compat | 0x20);
    let inode = 5 * 1024 + 256;
    bytes[inode + 40..inode + 100].fill(0);
    word(&mut bytes, inode + 40, 0xf30a);
    word(&mut bytes, inode + 44, 4);
    word(&mut bytes, inode + 56, 1);
    le(&mut bytes, inode + 60, 40);
    le(&mut bytes, inode + 4, 2048);
    le(&mut bytes, inode + 28, 4);
    le(&mut bytes, inode + 32, 0x81000);
    word(&mut bytes, inode + 42, 2);
    le(&mut bytes, inode + 64, 1);
    word(&mut bytes, inode + 68, 1);
    le(&mut bytes, inode + 72, 46);
    word(&mut bytes, inode + 124, 0);
    word(&mut bytes, inode + 130, 0);
    let checksum = crc(
        crc(crc(seed, &2u32.to_le_bytes()), &0u32.to_le_bytes()),
        &bytes[inode..inode + 256],
    );
    word(&mut bytes, inode + 124, checksum as u16);
    word(&mut bytes, inode + 130, (checksum >> 16) as u16);
    let root = 40 * 1024;
    bytes[root..root + 1024].fill(0);
    le(&mut bytes, root, 2);
    word(&mut bytes, root + 4, 12);
    bytes[root + 6] = 1;
    bytes[root + 7] = 2;
    bytes[root + 8] = b'.';
    le(&mut bytes, root + 12, 2);
    word(&mut bytes, root + 16, 1012);
    bytes[root + 18] = 2;
    bytes[root + 19] = 2;
    bytes[root + 20..root + 22].copy_from_slice(b"..");
    bytes[root + 28] = 1;
    bytes[root + 29] = 8;
    word(&mut bytes, root + 32, 123);
    word(&mut bytes, root + 34, 1);
    le(&mut bytes, root + 36, 1);
    let checksum = crc(
        crc(
            crc(crc(seed, &2u32.to_le_bytes()), &0u32.to_le_bytes()),
            &bytes[root..root + 40],
        ),
        &[0; 8],
    );
    le(&mut bytes, root + 1020, checksum);
    let leaf = 46 * 1024;
    bytes[leaf..leaf + 1024].fill(0);
    le(&mut bytes, leaf, 11);
    word(&mut bytes, leaf + 4, 1012);
    bytes[leaf + 6] = 4;
    bytes[leaf + 7] = 1;
    bytes[leaf + 8..leaf + 12].copy_from_slice(b"file");
    word(&mut bytes, leaf + 1016, 12);
    bytes[leaf + 1019] = 0xde;
    let checksum = crc(
        crc(crc(seed, &2u32.to_le_bytes()), &0u32.to_le_bytes()),
        &bytes[leaf..leaf + 1012],
    );
    le(&mut bytes, leaf + 1020, checksum);
    bytes[3 * 1024 + 45 / 8] |= 1 << (45 % 8);
    le(&mut bytes, 1036, 975);
    word(&mut bytes, 2048 + 12, 975);
    let checksum = crc(seed, &bytes[3 * 1024..3 * 1024 + 256]);
    word(&mut bytes, 2048 + 24, checksum as u16);
    word(&mut bytes, 2048 + 56, (checksum >> 16) as u16);
    word(&mut bytes, 2048 + 30, 0);
    let checksum = crc(crc(seed, &0u32.to_le_bytes()), &bytes[2048..2112]);
    word(&mut bytes, 2048 + 30, checksum as u16);
    let checksum = crc(!0, &bytes[1024..2044]);
    le(&mut bytes, 2044, checksum);
    bytes
}

#[cfg(feature = "std")]
#[test]
fn independent_htree_rename_preserves_index_hash_profile_and_payload() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = indexed_namespace_fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };
    let target = recovery::tests::Fault {
        visible: bytes.clone(),
        durable: bytes.clone(),
        events: 0,
        cut: usize::MAX,
        immediate: true,
        failed_flush_persists: true,
        torn: false,
    };
    let mut owner = session::Session::open(target, limits, &r).unwrap();
    owner
        .operate(
            session::Operation::Rename {
                source: &[],
                name: b"file",
                destination: &[],
                new_name: b"long-native-\xff",
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    let handle = owner
        .file_at(
            &[crate::fs_core::NativeName::Bytes(
                b"long-native-\xff".to_vec(),
            )],
            &r.cancellation,
        )
        .unwrap();
    assert_eq!(handle.inode_number(), 11);
    drop(handle);
    let (target, _) = owner.into_storage();
    assert_eq!(r.memory.used(), 0);
    let root = 5 * 1024 + 256;
    assert_eq!(
        u32::from_le_bytes(target.durable[root + 32..root + 36].try_into().unwrap()),
        0x81000
    );
    assert_eq!(
        &target.durable[41 * 1024..46 * 1024],
        &bytes[41 * 1024..46 * 1024]
    );
    let checked = session::Session::open(target, limits, &r).unwrap();
    drop(checked);
    assert_eq!(r.memory.used(), 0);
}

pub(super) fn independent_namespace_restart_matrix(
    bytes: Vec<u8>,
    limits: session::Limits,
    perform: impl Fn(
        &mut session::Session<recovery::tests::Fault>,
        &Cancellation,
    ) -> crate::platform::io::Result<()>,
) {
    let r = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let make = |immediate, failed_flush_persists, torn, cut| recovery::tests::Fault {
        visible: bytes.clone(),
        durable: bytes.clone(),
        events: 0,
        cut,
        immediate,
        failed_flush_persists,
        torn,
    };
    let mut owner =
        session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
    perform(&mut owner, &r.cancellation).unwrap();
    let (success, _) = owner.into_storage();
    assert_eq!(r.memory.used(), 0);
    for immediate in [false, true] {
        for failed_flush_persists in [false, true] {
            for torn in [false, true] {
                for cut in 1..=success.events {
                    let mut owner = session::Session::open(
                        make(immediate, failed_flush_persists, torn, cut),
                        limits,
                        &r,
                    )
                    .unwrap();
                    assert!(perform(&mut owner, &r.cancellation).is_err());
                    let (mut target, _) = owner.into_storage();
                    assert_eq!(r.memory.used(), 0);
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
                        target.durable[..100 * 1024] == expected[..100 * 1024]
                            && target.durable[1124 * 1024..] == expected[1124 * 1024..]
                    };
                    assert!(
                        home_matches(&bytes) || home_matches(&success.durable),
                        "namespace partial home cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                    );
                    let checked = session::Session::open(target, limits, &r).unwrap();
                    drop(checked);
                    assert_eq!(r.memory.used(), 0);
                }
            }
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn independent_htree_rename_restart_every_write_barrier_and_torn_cut() {
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 100000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 100000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };
    independent_namespace_restart_matrix(
        indexed_namespace_fixture(),
        limits,
        |owner, cancellation| {
            owner.operate(
                session::Operation::Rename {
                    source: &[],
                    name: b"file",
                    destination: &[],
                    new_name: b"long-native-\xff",
                },
                planning,
                cancellation,
            )
        },
    );
}

#[cfg(feature = "std")]
#[test]
fn independent_uninitialized_inode_group_restart_every_write_barrier_and_torn_cut() {
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 4096,
            inodes: 256,
            work: 4_000_000,
            directory_blocks: 8,
            directory_entries: 256,
            findings: 8,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 64,
        directory_entries: 256,
        affected_bytes: 1 << 20,
        work: 4_000_000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };
    let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100640);
    independent_namespace_restart_matrix(
        uninitialized_inode_group_fixture(),
        limits,
        |owner, cancellation| {
            owner.operate(
                session::Operation::CreateFile {
                    parent: &[],
                    name: b"new-\xff",
                    metadata: &metadata,
                    payload: &[],
                },
                planning,
                cancellation,
            )
        },
    );
}
