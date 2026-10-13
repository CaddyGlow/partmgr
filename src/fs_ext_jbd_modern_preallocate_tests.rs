//! Independent raw modern fixture, reservation semantic and zero-IO tests.
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
    let mut bytes = super::super::super::bootstrap::tests::fixture().0;
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

struct ReadOnly {
    bytes: Vec<u8>,
    writes: usize,
}
impl Storage for ReadOnly {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(
            self.bytes
                .get(at as usize..at as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        Err(io::Error::other("planning wrote storage"))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writes += 1;
        Err(io::Error::other("planning flushed storage"))
    }
}
fn limits() -> ExtEditLimits {
    ExtEditLimits {
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 2048,
            inodes: 128,
            work: 2_000_000,
            directory_blocks: 8,
            directory_entries: 32,
            findings: 8,
        },
        file_blocks: 64,
        directory_entries: 32,
        affected_bytes: 1 << 20,
        work: 2_000_000,
        undo: crate::fs_undo::UndoLimits {
            patches: 128,
            body_bytes: 4 << 20,
        },
    }
}
#[test]
fn native_unwritten_keep_size_beyond_eof_preserves_payload_and_refunds() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let storage = ReadOnly {
        bytes: fixture(),
        writes: 0,
    };
    let original = storage.bytes.clone();
    {
        let (decoder, proof) =
            crate::fs_ext::ExtDecoder::open_native_clean(&storage as &dyn Storage, 91, &r).unwrap();
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits().audit, &r).unwrap();
        assert!(audit.is_clean());
        let inode = decoder.inode(11, &r).unwrap();
        let plan = keep_size(&decoder, &audit, &inode, 8192, 4096, limits(), &r).unwrap();
        assert!(!plan.patches.is_empty());
        plan.check_source_guards(&storage, &r).unwrap();
        let mut drift = ReadOnly {
            bytes: original.clone(),
            writes: 0,
        };
        drift.bytes[5 * 1024 + 10 * 256 + 12] ^= 1;
        let guard_error = plan.check_source_guards(&drift, &r).unwrap_err();
        assert!(
            guard_error
                .to_string()
                .contains("reservation exact source guard changed")
        );
        assert_eq!(drift.writes, 0);
        let mut final_bytes = original.clone();
        for patch in &plan.patches {
            let at = patch.offset() as usize;
            assert_eq!(&original[at..at + patch.expected().len()], patch.expected());
            final_bytes[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
        }
        let final_store = ReadOnly {
            bytes: final_bytes,
            writes: 0,
        };
        let (after, after_proof) =
            crate::fs_ext::ExtDecoder::open_native_clean(&final_store as &dyn Storage, 92, &r)
                .unwrap();
        let after_audit = crate::fs_ext_audit::audit_decoder(&after, limits().audit, &r).unwrap();
        assert!(after_audit.is_clean());
        let final_inode = after.inode(11, &r).unwrap();
        assert_eq!(final_inode.length, inode.length);
        let map = after.extent_allocations(&final_inode, 64, &r).unwrap();
        for logical in 8..12 {
            assert!(map.allocations.iter().any(|a| a.logical <= logical
                && logical < a.logical + u64::from(a.blocks)
                && a.unwritten));
        }
        for block in 41..46 {
            assert_eq!(
                &final_store.bytes[block * 1024..(block + 1) * 1024],
                &original[block * 1024..(block + 1) * 1024]
            );
        }
        let repeat =
            keep_size(&after, &after_audit, &final_inode, 8192, 4096, limits(), &r).unwrap();
        assert!(repeat.patches.is_empty());
        drop((
            repeat,
            map,
            final_inode,
            after_audit,
            after,
            after_proof,
            plan,
            inode,
            audit,
            decoder,
            proof,
        ));
    }
    assert_eq!(storage.writes, 0);
    assert_eq!(storage.bytes, original);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn reservation_overflow_budget_and_cancellation_are_write_free() {
    for mode in 0..3 {
        let r = Resources {
            memory: Budget::new(64 << 20),
            cancellation: Cancellation::default(),
        };
        let storage = ReadOnly {
            bytes: fixture(),
            writes: 0,
        };
        {
            let (decoder, proof) =
                crate::fs_ext::ExtDecoder::open_native_clean(&storage as &dyn Storage, 91, &r)
                    .unwrap();
            let mut limits = limits();
            let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits.audit, &r).unwrap();
            let inode = decoder.inode(11, &r).unwrap();
            let (offset, length) = match mode {
                0 => (u64::MAX, 2),
                1 => {
                    limits.work = 0;
                    (8192, 4096)
                }
                _ => {
                    r.cancellation.cancel();
                    (8192, 4096)
                }
            };
            assert!(keep_size(&decoder, &audit, &inode, offset, length, limits, &r).is_err());
            drop((inode, audit, decoder, proof));
        }
        assert_eq!(storage.writes, 0);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn modern_controller_binding_and_owner_geometry_are_sealed() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let storage = ReadOnly {
        bytes: fixture(),
        writes: 0,
    };
    {
        let (decoder, proof) =
            crate::fs_ext::ExtDecoder::open_native_clean(&storage as &dyn Storage, 91, &r).unwrap();
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits().audit, &r).unwrap();
        let inode = decoder.inode(11, &r).unwrap();
        let mut plan = keep_size(&decoder, &audit, &inode, 8192, 4096, limits(), &r).unwrap();
        assert!(
            plan.validate_source_guards(91, 7, &decoder, &r, limits().work)
                .is_err()
        );
        assert!(plan.bind_source_guards(92, 7).is_err());
        plan.bind_source_guards(91, 7).unwrap();
        assert!(
            plan.validate_source_guards(91, 7, &decoder, &r, 0)
                .unwrap_err()
                .to_string()
                .contains("validation work")
        );
        assert!(plan.bind_source_guards(91, 7).is_err());
        plan.validate_source_guards(91, 7, &decoder, &r, limits().work)
            .unwrap();
        assert!(
            plan.validate_source_guards(91, 8, &decoder, &r, limits().work)
                .is_err()
        );
        assert!(
            plan.validate_source_guards(92, 7, &decoder, &r, limits().work)
                .is_err()
        );
        let owner_at = 5 * 1024 + 10 * 256;
        assert!(plan.inode_guard_geometry(owner_at, 256));
        assert!(!plan.inode_guard_geometry(owner_at + 256, 256));
        assert!(!plan.inode_guard_geometry(owner_at, 128));
        let guards = plan.source_guards.as_mut().unwrap();
        guards.bytes[0].0 += 1;
        assert!(
            guards
                .validate(91, 7, &decoder, &r, limits().work)
                .unwrap_err()
                .to_string()
                .contains("owner or range")
        );
        guards.bytes[0].0 -= 1;
        guards.bytes[0].1.pop();
        assert!(
            guards
                .validate(91, 7, &decoder, &r, limits().work)
                .unwrap_err()
                .to_string()
                .contains("owner or range")
        );
        drop((plan, inode, audit, decoder, proof));
    }
    assert_eq!(storage.writes, 0);
    assert_eq!(r.memory.used(), 0);
}

struct PublicationDrift {
    bytes: Vec<u8>,
    writes: usize,
    changed: bool,
}
impl Storage for PublicationDrift {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(
            self.bytes
                .get(at as usize..at as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.bytes[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        self.writes += 1;
        if !self.changed {
            self.bytes[5 * 1024 + 10 * 256 + 12] ^= 1;
            self.changed = true;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn modern_controller_retains_guards_after_preparation_writes() {
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let mut storage = PublicationDrift {
        bytes: fixture(),
        writes: 0,
        changed: false,
    };
    {
        let (decoder, proof) =
            crate::fs_ext::ExtDecoder::open_native_clean(&storage as &dyn Storage, 91, &r).unwrap();
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits().audit, &r).unwrap();
        let inode = decoder.inode(11, &r).unwrap();
        let mut plan = keep_size(&decoder, &audit, &inode, 8192, 4096, limits(), &r).unwrap();
        plan.bind_source_guards(91, 7).unwrap();
        let mut records: Vec<crate::fs_ext::jbd::ReplayBlock> = Vec::new();
        for patch in &plan.patches {
            let first = patch.offset() / 1024;
            let end = (patch.offset() + patch.replacement().len() as u64).div_ceil(1024);
            for block in first..end {
                if !records
                    .iter()
                    .any(|record| u64::from(record.destination) == block)
                {
                    let mut bytes = [0; 4096];
                    bytes[..1024].copy_from_slice(
                        &storage.bytes[block as usize * 1024..(block as usize + 1) * 1024],
                    );
                    records.push(crate::fs_ext::jbd::ReplayBlock {
                        destination: block as u32,
                        bytes,
                    });
                }
            }
        }
        for patch in &plan.patches {
            for (relative, byte) in patch.replacement().iter().enumerate() {
                let at = patch.offset() as usize + relative;
                records
                    .iter_mut()
                    .find(|record| record.destination as usize == at / 1024)
                    .unwrap()
                    .bytes[at % 1024] = *byte;
            }
        }
        // Match session projection: the controller retains RECOVER until checkpoint.
        let primary = records
            .iter_mut()
            .find(|record| record.destination == 1)
            .unwrap();
        let features = crate::fs_ext::u32le(&primary.bytes, 96) | 4;
        primary.bytes[96..100].copy_from_slice(&features.to_le_bytes());
        if decoder.geometry().modern.is_some() {
            let checksum = crate::fs_ext::checksum::crc32c(!0, &primary.bytes[..1020]);
            primary.bytes[1020..1024].copy_from_slice(&checksum.to_le_bytes());
        }
        drop((inode, audit, decoder, proof));
        let error = crate::fs_ext::jbd::transaction::commit_modern(
            &mut storage,
            91,
            7,
            limits().audit,
            128,
            1 << 20,
            &records,
            &plan,
            &r,
        )
        .err()
        .expect("controller must reject changed source");
        assert!(
            storage.changed && storage.writes > 0,
            "must reach durable preparation phase: {error}"
        );
        assert!(
            error
                .to_string()
                .contains("ordered original payload changed before publication"),
            "{error}"
        );
        drop((records, plan));
    }
    assert_eq!(r.memory.used(), 0);
}

fn session_limits() -> crate::fs_ext::jbd::session::Limits {
    crate::fs_ext::jbd::session::Limits {
        audit: limits().audit,
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    }
}

#[test]
fn session_keep_size_publishes_unwritten_ownership_and_noop_preserves_handle() {
    use crate::fs_ext::jbd::{recovery, session};
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let original = fixture();
    let storage = recovery::tests::Fault {
        visible: original.clone(),
        durable: original.clone(),
        events: 0,
        cut: usize::MAX,
        immediate: true,
        failed_flush_persists: true,
        torn: false,
    };
    let mut owner = session::Session::open(storage, session_limits(), &r).unwrap();
    let stale = owner.file(11, &r.cancellation).unwrap();
    owner
        .operate(
            session::Operation::PreallocateKeepSize {
                file: &stale,
                offset: 8192,
                length: 4096,
            },
            limits(),
            &r.cancellation,
        )
        .unwrap();
    assert!(
        owner
            .read_at(&stale, 0, &mut [0; 1], &r.cancellation)
            .is_err()
    );
    drop(stale);
    let file = owner.file(11, &r.cancellation).unwrap();
    // A reservation already covered by unwritten extents is an actual controller
    // no-op: it must retain this handle's generation and emit no publication IO.
    owner
        .operate(
            session::Operation::PreallocateKeepSize {
                file: &file,
                offset: 8192,
                length: 4096,
            },
            limits(),
            &r.cancellation,
        )
        .unwrap();
    let mut payload = [0; 4096];
    assert_eq!(
        owner
            .read_at(&file, 0, &mut payload, &r.cancellation)
            .unwrap(),
        3000
    );
    assert_eq!(&payload[..3000], &original[41 * 1024..41 * 1024 + 3000]);
    assert_eq!(
        owner
            .read_at(&file, 8192, &mut [0; 1], &r.cancellation)
            .unwrap(),
        0
    );
    drop(file);
    let (storage, _) = owner.into_storage();
    assert!(storage.events > 0);
    assert_eq!(storage.visible, storage.durable);
    let published_events = storage.events;
    let published = storage.durable.clone();
    let mut owner = session::Session::open(storage, session_limits(), &r).unwrap();
    let file = owner.file(11, &r.cancellation).unwrap();
    owner
        .operate(
            session::Operation::PreallocateKeepSize {
                file: &file,
                offset: 8192,
                length: 4096,
            },
            limits(),
            &r.cancellation,
        )
        .unwrap();
    drop(file);
    let (storage, _) = owner.into_storage();
    assert_eq!(storage.events, published_events);
    assert_eq!(storage.durable, published);
    {
        let (decoder, proof) =
            crate::fs_ext::ExtDecoder::open_native_clean(&storage, 92, &r).unwrap();
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits().audit, &r).unwrap();
        assert!(audit.is_clean(), "{:?}", audit.findings());
        let inode = decoder.inode(11, &r).unwrap();
        assert_eq!(inode.length, 3000);
        let map = decoder.extent_allocations(&inode, 64, &r).unwrap();
        for logical in 8..12 {
            assert!(map.allocations.iter().any(|a| a.logical <= logical
                && logical < a.logical + u64::from(a.blocks)
                && a.unwritten));
        }
        for block in 41..46 {
            assert_eq!(
                &storage.durable[block * 1024..(block + 1) * 1024],
                &original[block * 1024..(block + 1) * 1024]
            );
        }
        drop((map, inode, audit, decoder, proof));
    }
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn session_keep_size_rechecks_source_after_durable_preparation() {
    use crate::fs_ext::jbd::session;
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let storage = PublicationDrift {
        bytes: fixture(),
        writes: 0,
        changed: false,
    };
    let mut owner = session::Session::open(storage, session_limits(), &r).unwrap();
    let file = owner.file(11, &r.cancellation).unwrap();
    let error = owner
        .operate(
            session::Operation::PreallocateKeepSize {
                file: &file,
                offset: 8192,
                length: 4096,
            },
            limits(),
            &r.cancellation,
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ordered original payload changed before publication"),
        "{error}"
    );
    // Preparation failure invalidates the handle and keeps this owner recovery-fenced.
    assert!(
        owner
            .read_at(&file, 0, &mut [0; 1], &r.cancellation)
            .is_err()
    );
    drop(file);
    let (storage, state) = owner.into_storage();
    assert!(storage.changed && storage.writes > 0);
    assert_eq!(state, session::State::NeedsRecovery);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn session_keep_size_rejects_foreign_owner_before_publication() {
    use crate::fs_ext::jbd::session;
    let r = Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    };
    let original = fixture();
    let source = session::Session::open(
        ReadOnly {
            bytes: original.clone(),
            writes: 0,
        },
        session_limits(),
        &r,
    )
    .unwrap();
    let foreign = source.file(11, &r.cancellation).unwrap();
    let mut destination = session::Session::open(
        ReadOnly {
            bytes: original.clone(),
            writes: 0,
        },
        session_limits(),
        &r,
    )
    .unwrap();
    let error = destination
        .operate(
            session::Operation::PreallocateKeepSize {
                file: &foreign,
                offset: 8192,
                length: 4096,
            },
            limits(),
            &r.cancellation,
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("foreign or invalidated native ext file handle"),
        "{error}"
    );
    drop(foreign);
    drop(source);
    let (storage, state) = destination.into_storage();
    assert_eq!(state, session::State::Ready);
    assert_eq!(storage.writes, 0);
    assert_eq!(storage.bytes, original);
    assert_eq!(r.memory.used(), 0);
}
