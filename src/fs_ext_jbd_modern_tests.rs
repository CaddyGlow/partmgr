//! Independently assembled modern ownership/allocation fixtures and fault models.

use super::*;
use crate::fs_core::{Budget, Cancellation};
fn le(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn word(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
// Independently assembled disk fields and forward-polynomial checksums. No writer codec.
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
fn fixture() -> Vec<u8> {
    let mut bytes = bootstrap::tests::fixture().0;
    let old = bytes.clone();
    le(&mut bytes, 1024 + 12, 976);
    le(&mut bytes, 1024 + 16, 117);
    le(&mut bytes, 1024 + 96, 0xc2);
    le(&mut bytes, 1024 + 100, 0x443);
    word(&mut bytes, 1024 + 88, 256);
    word(&mut bytes, 1024 + 254, 64);
    word(&mut bytes, 1024 + 348, 32);
    word(&mut bytes, 1024 + 350, 32);
    bytes[1024 + 373] = 1;
    let seed = crc(!0, &bytes[1024 + 104..1024 + 120]);
    bytes[2048..2112].fill(0);
    for (at, value) in [(0, 3), (4, 4), (8, 5)] {
        le(&mut bytes, 2048 + at, value);
    }
    for (at, value) in [(12, 976), (14, 117), (16, 1), (18, 4), (28, 117)] {
        word(&mut bytes, 2048 + at, value);
    }
    bytes[3 * 1024..5 * 1024].fill(0);
    for bit in 0..8192 {
        let physical = bit + 1;
        if bit >= 2047
            || (1..37).contains(&physical)
            || (40..46).contains(&physical)
            || (50..55).contains(&physical)
            || (100..1124).contains(&physical)
        {
            bytes[3 * 1024 + bit / 8] |= 1 << (bit % 8);
        }
        if !(11..128).contains(&bit) {
            bytes[4 * 1024 + bit / 8] |= 1 << (bit % 8);
        }
    }
    let block_crc = crc(seed, &bytes[3 * 1024..3 * 1024 + 256]);
    let inode_crc = crc(seed, &bytes[4 * 1024..4 * 1024 + 16]);
    word(&mut bytes, 2048 + 24, block_crc as u16);
    word(&mut bytes, 2048 + 56, (block_crc >> 16) as u16);
    word(&mut bytes, 2048 + 26, inode_crc as u16);
    word(&mut bytes, 2048 + 58, (inode_crc >> 16) as u16);
    let descriptor_crc = crc(crc(seed, &0u32.to_le_bytes()), &bytes[2048..2112]);
    word(&mut bytes, 2048 + 30, descriptor_crc as u16);
    bytes[5 * 1024..37 * 1024].fill(0);
    for number in 1..=11 {
        let at = 5 * 1024 + (number - 1) * 256;
        if number <= 10 {
            bytes[at..at + 128]
                .copy_from_slice(&old[5 * 1024 + (number - 1) * 128..5 * 1024 + number * 128]);
        }
        word(&mut bytes, at + 128, 32);
        if number == 2 {
            le(&mut bytes, at + 40, 40);
        }
        if number == 11 {
            word(&mut bytes, at, 0o100640);
            word(&mut bytes, at + 26, 1);
            le(&mut bytes, at + 4, 3000);
            le(&mut bytes, at + 28, 10);
            le(&mut bytes, at + 32, 0x80000);
            word(&mut bytes, at + 40, 0xf30a);
            word(&mut bytes, at + 42, 2);
            word(&mut bytes, at + 44, 4);
            word(&mut bytes, at + 56, 3);
            le(&mut bytes, at + 60, 41);
            le(&mut bytes, at + 64, 3);
            word(&mut bytes, at + 68, 32770);
            le(&mut bytes, at + 72, 44);
        }
        let inode_crc = crc(
            crc(
                crc(seed, &(number as u32).to_le_bytes()),
                &0u32.to_le_bytes(),
            ),
            &bytes[at..at + 256],
        );
        word(&mut bytes, at + 124, inode_crc as u16);
        word(&mut bytes, at + 130, (inode_crc >> 16) as u16);
    }
    let at = 40 * 1024;
    bytes[at..at + 1024].fill(0);
    for (relative, inode, length, name, kind) in [
        (0, 2, 12, b".".as_slice(), 2),
        (12, 2, 12, b"..".as_slice(), 2),
        (24, 11, 988, b"file".as_slice(), 1),
    ] {
        le(&mut bytes, at + relative, inode);
        word(&mut bytes, at + relative + 4, length);
        bytes[at + relative + 6] = name.len() as u8;
        bytes[at + relative + 7] = kind;
        bytes[at + relative + 8..at + relative + 8 + name.len()].copy_from_slice(name);
    }
    word(&mut bytes, at + 1016, 12);
    bytes[at + 1019] = 0xde;
    let directory_crc = crc(
        crc(crc(seed, &2u32.to_le_bytes()), &0u32.to_le_bytes()),
        &bytes[at..at + 1012],
    );
    le(&mut bytes, at + 1020, directory_crc);
    for (index, byte) in bytes[41 * 1024..44 * 1024].iter_mut().enumerate() {
        *byte = (index * 37 + index / 19) as u8;
    }
    bytes[44 * 1024..46 * 1024].fill(0xa7);
    let checksum = crc(!0, &bytes[1024..1024 + 1020]);
    le(&mut bytes, 1024 + 1020, checksum);
    bytes
}
#[test]
fn independent_modern_extent_truncate_unwritten_ownership_checksum_and_refunds() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = fixture();
    let mut storage = recovery::tests::Fault {
        visible: bytes.clone(),
        durable: bytes.clone(),
        events: 0,
        cut: usize::MAX,
        immediate: true,
        failed_flush_persists: true,
        torn: false,
    };
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
        let (decoder, proof) =
            super::super::super::ExtDecoder::open_native_clean(&storage, 18u128 << 64, &r).unwrap();
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits.audit, &r).unwrap();
        assert!(audit.is_clean(), "{:?}", audit.findings());
        drop((decoder, proof, audit));
    }
    let mut owner = session::Session::open(storage, limits, &r).unwrap();
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
    assert!(
        owner
            .read_at(&file, 0, &mut [0; 1], &r.cancellation)
            .is_err()
    );
    drop(file);
    let file = owner.file(11, &r.cancellation).unwrap();
    let mut prefix = [0; 513];
    assert_eq!(
        owner
            .read_at(&file, 0, &mut prefix, &r.cancellation)
            .unwrap(),
        513
    );
    assert_eq!(&prefix, &bytes[41 * 1024..41 * 1024 + 513]);
    drop(file);
    let file = owner.file(11, &r.cancellation).unwrap();
    owner
        .operate(
            session::Operation::Truncate {
                file: &file,
                length: 0,
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    drop(file);
    (storage, _) = owner.into_storage();
    assert_eq!(
        &storage.durable[42 * 1024..46 * 1024],
        &bytes[42 * 1024..46 * 1024]
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn modern_truncate_restart_every_write_barrier_and_torn_cut() {
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

    for length in [513, 0] {
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
            let file = owner.file(11, &r.cancellation).unwrap();
            owner.operate(
                session::Operation::Truncate {
                    file: &file,
                    length,
                },
                planning,
                &r.cancellation,
            )
        };
        let mut success =
            session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
        perform(&mut success).unwrap();
        let (success, _) = success.into_storage();
        let events = success.events;
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
                            "partial modern home length={length} cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}
struct Input {
    identity: crate::fs_core::ObjectId,
    bytes: Vec<u8>,
}
impl crate::fs_core::FileRead for Input {
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
#[test]
fn modern_deferred_append_unwritten_conversion_indexed_extents_then_truncate() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 1000000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 512,
        affected_blocks: 512,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 512,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 1000000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };

    let input = Input {
        identity: crate::fs_core::ObjectId {
            source: 99,
            generation: 1,
            native: vec![7],
        },
        bytes: (0..100013).map(|n| (n * 19 + n / 31) as u8).collect(),
    };
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
    assert!(
        owner
            .read_at(&file, 0, &mut [0; 1], &r.cancellation)
            .is_err()
    );
    drop(file);
    let file = owner.file(11, &r.cancellation).unwrap();
    let mut actual = vec![0; 103013];
    assert_eq!(
        owner
            .read_at(&file, 0, &mut actual, &r.cancellation)
            .unwrap(),
        actual.len()
    );
    assert_eq!(&actual[..3000], &bytes[41 * 1024..41 * 1024 + 3000]);
    assert_eq!(&actual[3000..], &input.bytes);
    owner
        .operate(
            session::Operation::Truncate {
                file: &file,
                length: 90000,
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    drop(file);
    let file = owner.file(11, &r.cancellation).unwrap();
    let mut prefix = vec![0; 90000];
    assert_eq!(
        owner
            .read_at(&file, 0, &mut prefix, &r.cancellation)
            .unwrap(),
        prefix.len()
    );
    assert_eq!(prefix, &actual[..90000]);
    owner
        .operate(
            session::Operation::Truncate {
                file: &file,
                length: 0,
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    drop(file);
    drop(owner);
    assert_eq!(r.memory.used(), 0);
}
fn fragmented_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    let at = 5 * 1024 + 10 * 256;
    let mut inode = bytes[at..at + 256].to_vec();
    inode[40..100].fill(0);
    word(&mut inode, 40, 0xf30a);
    word(&mut inode, 42, 1);
    word(&mut inode, 44, 4);
    word(&mut inode, 46, 2);
    le(&mut inode, 56, 46);
    le(&mut inode, 4, 799 * 1024);
    le(&mut inode, 28, 812);
    let seed = crc(
        crc(crc(!0, &[0x39; 16]), &11u32.to_le_bytes()),
        &0u32.to_le_bytes(),
    );
    for leaf in 0..5 {
        let physical = 41 + leaf;
        let block = &mut bytes[physical * 1024..(physical + 1) * 1024];
        block.fill(0);
        word(block, 0, 0xf30a);
        word(block, 2, (400 - leaf * 84).min(84) as u16);
        word(block, 4, 84);
        for relative in 0..(400 - leaf * 84).min(84) {
            let index = leaf * 84 + relative;
            let at = 12 + relative * 12;
            le(block, at, (index * 2) as u32);
            word(block, at + 4, 1);
            le(block, at + 8, (1130 + index * 2) as u32);
        }
        let checksum = crc(seed, &block[..1020]);
        le(block, 1020, checksum);
    }
    let parent = &mut bytes[46 * 1024..47 * 1024];
    parent.fill(0);
    word(parent, 0, 0xf30a);
    word(parent, 2, 5);
    word(parent, 4, 84);
    word(parent, 6, 1);
    for leaf in 0..5 {
        le(parent, 12 + leaf * 12, (leaf * 168) as u32);
        le(parent, 16 + leaf * 12, (41 + leaf) as u32);
    }
    let checksum = crc(seed, &parent[..1020]);
    le(parent, 1020, checksum);
    for index in 0..400 {
        let physical = 1130 + index * 2;
        bytes[3 * 1024 + (physical - 1) / 8] |= 1 << ((physical - 1) % 8);
        bytes[physical * 1024..(physical + 1) * 1024].fill((index * 17) as u8);
    }
    bytes[3 * 1024 + (46 - 1) / 8] |= 1 << ((46 - 1) % 8);
    le(&mut bytes, 1024 + 12, 575);
    word(&mut bytes, 2048 + 12, 575);
    let bitmap_crc = crc(crc(!0, &[0x39; 16]), &bytes[3 * 1024..3 * 1024 + 256]);
    word(&mut bytes, 2048 + 24, bitmap_crc as u16);
    word(&mut bytes, 2048 + 56, (bitmap_crc >> 16) as u16);
    word(&mut bytes, 2048 + 30, 0);
    let descriptor_crc = crc(
        crc(crc(!0, &[0x39; 16]), &0u32.to_le_bytes()),
        &bytes[2048..2112],
    );
    word(&mut bytes, 2048 + 30, descriptor_crc as u16);
    word(&mut inode, 124, 0);
    word(&mut inode, 130, 0);
    let inode_crc = crc(seed, &inode);
    word(&mut inode, 124, inode_crc as u16);
    word(&mut inode, 130, (inode_crc >> 16) as u16);
    bytes[at..at + 256].copy_from_slice(&inode);
    let super_crc = crc(!0, &bytes[1024..2044]);
    le(&mut bytes, 2044, super_crc);
    bytes
}
#[test]
fn independent_depth_two_extent_writer_preserves_sparse_holes_and_refunds() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = fragmented_fixture();
    let storage = recovery::tests::Fault {
        visible: bytes.clone(),
        durable: bytes,
        events: 0,
        cut: usize::MAX,
        immediate: true,
        failed_flush_persists: true,
        torn: false,
    };
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 1000000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 1024,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: limits.file_blocks,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 1000000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };
    {
        let (decoder, proof) =
            super::super::super::ExtDecoder::open_native_clean(&storage, 18u128 << 64, &r).unwrap();
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits.audit, &r).unwrap();
        assert!(audit.is_clean(), "{:?}", audit.findings());
        drop((decoder, proof, audit));
    }
    let mut owner = session::Session::open(storage, limits, &r).unwrap();
    let file = owner.file(11, &r.cancellation).unwrap();
    owner
        .operate(
            session::Operation::Truncate {
                file: &file,
                length: 790 * 1024,
            },
            planning,
            &r.cancellation,
        )
        .unwrap();
    drop(file);
    let file = owner.file(11, &r.cancellation).unwrap();
    for logical in [0, 1, 168, 169, 788, 789] {
        let mut block = [0; 1024];
        assert_eq!(
            owner
                .read_at(&file, logical * 1024, &mut block, &r.cancellation)
                .unwrap(),
            1024
        );
        let byte = if logical % 2 == 0 {
            (logical / 2 * 17) as u8
        } else {
            0
        };
        assert!(block.iter().all(|b| *b == byte));
    }
    drop(file);
    drop(owner);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn modern_append_indexed_restart_every_write_barrier_and_torn_cut() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = fixture();
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 1000000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 512,
        affected_blocks: 512,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 512,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 1000000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };

    let input = Input {
        identity: crate::fs_core::ObjectId {
            source: 99,
            generation: 1,
            native: vec![7],
        },
        bytes: (0..60013).map(|n| (n * 19 + n / 31) as u8).collect(),
    };
    for length in [input.bytes.len()] {
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
            let file = owner.file(11, &r.cancellation).unwrap();
            owner.operate(
                session::Operation::Extend {
                    file: &file,
                    input: &input,
                },
                planning,
                &r.cancellation,
            )
        };
        let mut success =
            session::Session::open(make(true, true, false, usize::MAX), limits, &r).unwrap();
        perform(&mut success).unwrap();
        let (success, _) = success.into_storage();
        let events = success.events;
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
                            "partial modern home length={length} cut={cut} immediate={immediate} flush={failed_flush_persists} torn={torn}"
                        );
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
    }
}
struct BadInput {
    inner: Input,
    next: crate::fs_core::ObjectId,
    changed: std::sync::atomic::AtomicBool,
    kind: u8,
}
impl crate::fs_core::FileRead for BadInput {
    fn identity(&self) -> &crate::fs_core::ObjectId {
        if self.kind == 0 && self.changed.load(std::sync::atomic::Ordering::Relaxed) {
            &self.next
        } else {
            &self.inner.identity
        }
    }
    fn len(&self) -> u64 {
        self.inner.bytes.len() as u64
            + u64::from(self.kind == 1 && self.changed.load(std::sync::atomic::Ordering::Relaxed))
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> crate::fs_core::Result<usize> {
        if self.kind == 2 {
            return Ok(0);
        }
        if self.kind == 3 {
            return Ok(out.len() + 1);
        }
        let n = crate::fs_core::FileRead::read_at(&self.inner, at, out, r)?;
        self.changed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if self.kind == 4 {
            r.cancellation.cancel();
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visitor: &mut dyn FnMut(crate::fs_core::LogicalExtent) -> crate::fs_core::Result<()>,
    ) -> crate::fs_core::Result<()> {
        crate::fs_core::FileRead::visit_extents(&self.inner, r, visitor)
    }
}
#[test]
fn modern_append_deferred_failures_caps_and_cancellation_write_nothing() {
    for kind in 0..7 {
        let r = Resources {
            memory: Budget::new(64 << 20),
            cancellation: Cancellation::default(),
        };
        let bytes = fixture();
        let storage = recovery::tests::Fault {
            visible: bytes.clone(),
            durable: bytes.clone(),
            events: 0,
            cut: usize::MAX,
            immediate: true,
            failed_flush_persists: true,
            torn: false,
        };
        let limits = session::Limits {
            audit: crate::fs_ext_audit::ExtAuditLimits {
                blocks: 2048,
                inodes: 128,
                work: 1000000,
                directory_blocks: 8,
                directory_entries: 32,
                findings: 8,
            },
            file_blocks: 512,
            affected_blocks: 512,
            affected_bytes: 1 << 20,
        };
        let mut planning = ExtEditLimits {
            audit: limits.audit,
            file_blocks: 512,
            directory_entries: 32,
            affected_bytes: 1 << 20,
            work: 1000000,
            undo: crate::fs_undo::UndoLimits {
                patches: 1024,
                body_bytes: 4 << 20,
            },
        };
        if kind == 5 {
            planning.affected_bytes = 32;
        }
        if kind == 6 {
            planning.work = 8;
        }
        let input = BadInput {
            inner: Input {
                identity: crate::fs_core::ObjectId {
                    source: 99,
                    generation: 1,
                    native: vec![7],
                },
                bytes: vec![0x79; 8193],
            },
            next: crate::fs_core::ObjectId {
                source: 99,
                generation: 2,
                native: vec![7],
            },
            changed: std::sync::atomic::AtomicBool::new(false),
            kind,
        };
        let mut owner = session::Session::open(storage, limits, &r).unwrap();
        let file = owner.file(11, &r.cancellation).unwrap();
        assert!(
            owner
                .operate(
                    session::Operation::Extend {
                        file: &file,
                        input: &input
                    },
                    planning,
                    &r.cancellation
                )
                .is_err()
        );
        drop(file);
        let (target, state) = owner.into_storage();
        assert_eq!(state, session::State::Ready);
        assert_eq!(target.events, 0);
        assert_eq!(target.visible, bytes);
        assert_eq!(target.durable, bytes);
        assert_eq!(r.memory.used(), 0);
    }
}
fn uninitialized_second_group_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    bytes.resize(4096 * 1024, 0);
    le(&mut bytes, 1024, 256);
    le(&mut bytes, 1024 + 4, 4096);
    le(&mut bytes, 1024 + 12, 2988);
    le(&mut bytes, 1024 + 16, 245);
    let seed = crc(!0, &[0x39; 16]);
    bytes[3 * 1024 + 255] &= 0x7f;
    word(&mut bytes, 2048 + 12, 977);
    let bitmap_crc = crc(seed, &bytes[3 * 1024..3 * 1024 + 256]);
    word(&mut bytes, 2048 + 24, bitmap_crc as u16);
    word(&mut bytes, 2048 + 56, (bitmap_crc >> 16) as u16);
    word(&mut bytes, 2048 + 30, 0);
    let descriptor_crc = crc(crc(seed, &0u32.to_le_bytes()), &bytes[2048..2112]);
    word(&mut bytes, 2048 + 30, descriptor_crc as u16);

    let mut descriptor = [0; 64];
    le(&mut descriptor, 0, 2051);
    le(&mut descriptor, 4, 2052);
    le(&mut descriptor, 8, 2053);
    word(&mut descriptor, 12, 2011);
    word(&mut descriptor, 14, 128);
    word(&mut descriptor, 18, 7);
    word(&mut descriptor, 28, 128);
    let checksum = crc(crc(seed, &1u32.to_le_bytes()), &descriptor);
    word(&mut descriptor, 30, checksum as u16);
    bytes[2112..2176].copy_from_slice(&descriptor);
    let checksum = crc(!0, &bytes[1024..2044]);
    le(&mut bytes, 2044, checksum);
    let mut backup = bytes[1024..2048].to_vec();
    word(&mut backup, 90, 1);
    le(&mut backup, 1020, 0);
    let checksum = crc(!0, &backup[..1020]);
    le(&mut backup, 1020, checksum);
    bytes[2049 * 1024..2050 * 1024].copy_from_slice(&backup);
    let table = bytes[2048..3072].to_vec();
    bytes[2050 * 1024..2051 * 1024].copy_from_slice(&table);
    bytes[2051 * 1024..2053 * 1024].fill(0xa7);
    bytes
}
#[test]
fn modern_allocate_materializes_uninitialized_bitmap_preserving_inode_flags() {
    let r = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = uninitialized_second_group_fixture();
    let storage = recovery::tests::Fault {
        visible: bytes.clone(),
        durable: bytes.clone(),
        events: 0,
        cut: usize::MAX,
        immediate: true,
        failed_flush_persists: true,
        torn: false,
    };
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 4096,
            inodes: 256,
            work: 4000000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 1200,
        affected_blocks: 1200,
        affected_bytes: 16 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 1200,
        directory_entries: 32,
        affected_bytes: 16 << 20,
        work: 4000000,
        undo: crate::fs_undo::UndoLimits {
            patches: 4096,
            body_bytes: 32 << 20,
        },
    };
    {
        let (decoder, proof) =
            super::super::super::ExtDecoder::open_native_clean(&storage, 18u128 << 64, &r).unwrap();
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits.audit, &r).unwrap();
        assert!(audit.is_clean(), "{:?}", audit.findings());
        drop((decoder, proof, audit));
    }
    let input = Input {
        identity: crate::fs_core::ObjectId {
            source: 99,
            generation: 1,
            native: vec![7],
        },
        bytes: (0..980 * 1024).map(|n| (n * 13 + n / 41) as u8).collect(),
    };
    let mut owner = session::Session::open(storage, limits, &r).unwrap();
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
    let file = owner.file(11, &r.cancellation).unwrap();
    let mut tail = [0; 1024];
    let offset = 3000 + input.bytes.len() as u64 - 1024;
    assert_eq!(
        owner
            .read_at(&file, offset, &mut tail, &r.cancellation)
            .unwrap(),
        1024
    );
    assert_eq!(&tail, &input.bytes[input.bytes.len() - 1024..]);
    drop(file);
    let (target, _) = owner.into_storage();
    assert_eq!(super::super::super::u16le(&target.durable, 2112 + 18), 5);
    assert_ne!(
        &target.durable[2051 * 1024..2052 * 1024],
        &bytes[2051 * 1024..2052 * 1024]
    );
    assert_eq!(
        &target.durable[2052 * 1024..2053 * 1024],
        &bytes[2052 * 1024..2053 * 1024]
    );
    assert_eq!(r.memory.used(), 0);
}
fn full_fixture() -> Vec<u8> {
    let mut bytes = fixture();
    bytes[3 * 1024..4 * 1024].fill(0xff);
    le(&mut bytes, 1024 + 12, 0);
    word(&mut bytes, 2048 + 12, 0);
    let seed = crc(!0, &[0x39; 16]);
    let bitmap_crc = crc(seed, &bytes[3 * 1024..3 * 1024 + 256]);
    word(&mut bytes, 2048 + 24, bitmap_crc as u16);
    word(&mut bytes, 2048 + 56, (bitmap_crc >> 16) as u16);
    word(&mut bytes, 2048 + 30, 0);
    let descriptor_crc = crc(crc(seed, &0u32.to_le_bytes()), &bytes[2048..2112]);
    word(&mut bytes, 2048 + 30, descriptor_crc as u16);
    let at = 5 * 1024 + 10 * 256;
    let inode = &mut bytes[at..at + 256];
    inode[40..100].fill(0);
    le(inode, 4, 981 * 1024);
    le(inode, 28, 1962);
    word(inode, 40, 0xf30a);
    word(inode, 42, 4);
    word(inode, 44, 4);
    for (index, (logical, physical, length)) in
        [(0, 37, 3), (3, 41, 9), (12, 55, 45), (57, 1124, 924)]
            .into_iter()
            .enumerate()
    {
        let at = 52 + index * 12;
        le(inode, at, logical);
        word(inode, at + 4, length);
        le(inode, at + 8, physical);
    }
    word(inode, 124, 0);
    word(inode, 130, 0);
    let checksum = crc(
        crc(crc(seed, &11u32.to_le_bytes()), &0u32.to_le_bytes()),
        inode,
    );
    word(inode, 124, checksum as u16);
    word(inode, 130, (checksum >> 16) as u16);
    let checksum = crc(!0, &bytes[1024..2044]);
    le(&mut bytes, 2044, checksum);
    bytes
}
#[test]
fn modern_out_of_space_rejects_clean_fully_owned_volume_without_mutation() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let bytes = full_fixture();
    let storage = recovery::tests::Fault {
        visible: bytes.clone(),
        durable: bytes.clone(),
        events: 0,
        cut: usize::MAX,
        immediate: true,
        failed_flush_persists: true,
        torn: false,
    };
    let limits = session::Limits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 1000000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 1200,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    };
    let planning = ExtEditLimits {
        audit: limits.audit,
        file_blocks: 1200,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 1000000,
        undo: crate::fs_undo::UndoLimits {
            patches: 1024,
            body_bytes: 4 << 20,
        },
    };
    let input = Input {
        identity: crate::fs_core::ObjectId {
            source: 99,
            generation: 1,
            native: vec![7],
        },
        bytes: vec![0x79],
    };
    let mut owner = session::Session::open(storage, limits, &r).unwrap();
    let file = owner.file(11, &r.cancellation).unwrap();
    let error = owner
        .operate(
            session::Operation::Extend {
                file: &file,
                input: &input,
            },
            planning,
            &r.cancellation,
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    assert_eq!(
        owner
            .read_at(&file, 0, &mut [0; 1], &r.cancellation)
            .unwrap(),
        1
    );
    drop(file);
    let (target, state) = owner.into_storage();
    assert_eq!(state, session::State::Ready);
    assert_eq!(target.events, 0);
    assert_eq!(target.visible, bytes);
    assert_eq!(target.durable, bytes);
    assert_eq!(r.memory.used(), 0);
}

#[path = "fs_ext_jbd_modern_namespace_tests.rs"]
mod namespace_tests;

#[path = "fs_ext_jbd_modern_indirect_tests.rs"]
mod indirect_tests;

#[test]
fn independent_legacy_checksum_policy_allocation_namespace_projection() {
    for extents in [false, true] {
        for group16 in [false, true] {
            let (bytes, payload) =
                super::super::super::modern::tests::independent::without_metadata_checksums(
                    extents, group16,
                );
            let r = Resources {
                memory: Budget::new(64 << 20),
                cancellation: Cancellation::default(),
            };
            let mut storage = recovery::tests::Fault {
                visible: bytes.clone(),
                durable: bytes,
                events: 0,
                cut: usize::MAX,
                immediate: true,
                failed_flush_persists: true,
                torn: false,
            };
            let limits = ExtEditLimits {
                audit: crate::fs_ext_audit::ExtAuditLimits {
                    blocks: 128,
                    inodes: 32,
                    work: 100000,
                    directory_blocks: 16,
                    directory_entries: 32,
                    findings: 32,
                },
                file_blocks: 16,
                directory_entries: 32,
                affected_bytes: 1 << 20,
                work: 100000,
                undo: crate::fs_undo::UndoLimits {
                    patches: 128,
                    body_bytes: 4 << 20,
                },
            };
            let projected = {
                let decoder =
                    super::super::super::ExtDecoder::open_legacy_structural_qualification(
                        &storage as &dyn crate::storage::Storage,
                        18u128 << 64,
                        &r,
                    )
                    .unwrap();
                let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits.audit, &r).unwrap();
                assert!(audit.is_clean(), "{:?}", audit.findings());
                let inode = decoder.inode(12, &r).unwrap();
                let plan = truncate(&decoder, &audit, &inode, 513, limits, &r).unwrap();
                let mut projected = storage.visible.clone();
                for patch in &plan.patches {
                    let at = patch.offset() as usize;
                    assert_eq!(
                        &projected[at..at + patch.expected().len()],
                        patch.expected()
                    );
                    projected[at..at + patch.replacement().len()]
                        .copy_from_slice(patch.replacement());
                }
                projected
            };
            assert_eq!(r.memory.used(), 0);
            assert_eq!(storage.events, 0);
            // The absent checksum bytes and existing inode extension are opaque.
            let at = 5 * 1024 + 11 * 256;
            assert_eq!(
                &projected[at + 124..at + 126],
                &storage.visible[at + 124..at + 126]
            );
            assert_eq!(
                &projected[at + 128..at + 256],
                &storage.visible[at + 128..at + 256]
            );
            storage.visible = projected;
            let decoder = super::super::super::ExtDecoder::open_legacy_structural_qualification(
                &storage as &dyn crate::storage::Storage,
                18u128 << 64,
                &r,
            )
            .unwrap();
            let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits.audit, &r).unwrap();
            assert!(audit.is_clean(), "{:?}", audit.findings());
            let map = decoder.file_map(12, 16, &r, false).unwrap();
            let mut out = [0; 1024];
            assert_eq!(decoder.read_map(&map, 0, &mut out, &r).unwrap(), 513);
            assert_eq!(&out[..513], &payload[..513]);
            drop((map, audit, decoder));
            assert_eq!(r.memory.used(), 0);
            let file_metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100640);
            let directory_metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o40750);
            let born: Vec<u8> = (0..2057).map(|n| (n * 37 + n / 13) as u8).collect();
            let child = [crate::fs_core::NativeName::Bytes(b"child".to_vec())];
            for operation in 0..5 {
                let projected = {
                    let decoder =
                        super::super::super::ExtDecoder::open_legacy_structural_qualification(
                            &storage as &dyn crate::storage::Storage,
                            18u128 << 64,
                            &r,
                        )
                        .unwrap();
                    let audit =
                        crate::fs_ext_audit::audit_decoder(&decoder, limits.audit, &r).unwrap();
                    assert!(
                        audit.is_clean(),
                        "operation={operation} {:?}",
                        audit.findings()
                    );
                    let plan = match operation {
                        0 => create(
                            &decoder,
                            &audit,
                            Create {
                                parent: &[],
                                name: b"child",
                                metadata: &directory_metadata,
                                payload: &[],
                                directory: true,
                            },
                            limits,
                            &r,
                        ),
                        1 => create(
                            &decoder,
                            &audit,
                            Create {
                                parent: &[],
                                name: b"new\xfe",
                                metadata: &file_metadata,
                                payload: &born,
                                directory: false,
                            },
                            limits,
                            &r,
                        ),
                        2 => rename(
                            &decoder,
                            &audit,
                            Rename {
                                source: &[],
                                old_name: b"new\xfe",
                                destination: &child,
                                new_name: b"moved\xff",
                            },
                            limits,
                            &r,
                        ),
                        3 => delete(
                            &decoder,
                            &audit,
                            Delete {
                                parent: &child,
                                name: b"moved\xff",
                                deletion_time: 1234567,
                            },
                            limits,
                            &r,
                        ),
                        _ => delete(
                            &decoder,
                            &audit,
                            Delete {
                                parent: &[],
                                name: b"child",
                                deletion_time: 1234567,
                            },
                            limits,
                            &r,
                        ),
                    }
                    .unwrap();
                    let mut projected = storage.visible.clone();
                    for patch in &plan.patches {
                        let at = patch.offset() as usize;
                        assert_eq!(
                            &projected[at..at + patch.expected().len()],
                            patch.expected()
                        );
                        projected[at..at + patch.replacement().len()]
                            .copy_from_slice(patch.replacement());
                    }
                    projected
                };
                assert_eq!(r.memory.used(), 0);
                assert_eq!(storage.events, 0);
                storage.visible = projected;
                let decoder =
                    super::super::super::ExtDecoder::open_legacy_structural_qualification(
                        &storage as &dyn crate::storage::Storage,
                        18u128 << 64,
                        &r,
                    )
                    .unwrap();
                let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits.audit, &r).unwrap();
                assert!(
                    audit.is_clean(),
                    "after operation={operation} {:?}",
                    audit.findings()
                );
                if matches!(operation, 1 | 2) {
                    let directory = if operation == 1 {
                        decoder.directory(2, 16, 32, &r).unwrap()
                    } else {
                        let root = decoder.directory(2, 16, 32, &r).unwrap();
                        let number = root
                            .entries()
                            .iter()
                            .find(|e| e.name == child[0])
                            .unwrap()
                            .inode;
                        decoder.directory(number, 16, 32, &r).unwrap()
                    };
                    let name = if operation == 1 {
                        b"new\xfe".as_slice()
                    } else {
                        b"moved\xff".as_slice()
                    };
                    let number = directory.entries().iter().find(|e| matches!(&e.name, crate::fs_core::NativeName::Bytes(n) if n == name)).unwrap().inode;
                    let map = decoder.file_map(number, 16, &r, false).unwrap();
                    let mut out = vec![0; born.len()];
                    assert_eq!(decoder.read_map(&map, 0, &mut out, &r).unwrap(), born.len());
                    assert_eq!(out, born);
                }
                drop((audit, decoder));
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}
