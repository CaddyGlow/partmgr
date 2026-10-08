#![cfg(feature = "std")]

#[path = "fixtures/ext2_clean.rs"]
mod independent;
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, NativeName, Resources},
    fs_ext_audit::ExtAuditLimits,
    fs_ext_edit::{ExtEditBinding, ExtEditLimits, ExtEditRegion, ExtEditState, ExtEditor},
    fs_undo::UndoLimits,
    storage::Storage,
};
use std::io;
const BASE: usize = 4096;
struct Memory {
    bytes: Vec<u8>,
    writes: usize,
}
impl Storage for Memory {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(
            self.bytes
                .get(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(b.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        self.bytes
            .get_mut(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn container() -> Vec<u8> {
    let image = independent::fixture();
    let mut b = vec![0xa5; BASE + image.len() + BASE];
    b[BASE..BASE + image.len()].copy_from_slice(&image);
    b[BASE + image.len()..].fill(0x5a);
    b
}
fn r() -> Resources {
    Resources {
        memory: Budget::new(2 << 20),
        cancellation: Cancellation::default(),
    }
}
fn l() -> ExtEditLimits {
    ExtEditLimits {
        audit: ExtAuditLimits {
            blocks: 64,
            inodes: 16,
            work: 65536,
            directory_blocks: 4,
            directory_entries: 32,
            findings: 32,
        },
        file_blocks: 32,
        directory_entries: 32,
        affected_bytes: 8192,
        work: 4096,
        undo: UndoLimits {
            patches: 64,
            body_bytes: 32768,
        },
    }
}
fn binding() -> ExtEditBinding {
    ExtEditBinding {
        volume: [3; 32],
        generation: 7,
    }
}
fn region() -> ExtEditRegion {
    ExtEditRegion {
        offset: BASE as u64,
        length: 65536,
    }
}
fn open(bytes: Vec<u8>, r: &Resources) -> partmgr::fs_core::Result<ExtEditor<Memory, Memory>> {
    ExtEditor::open(
        Memory { bytes, writes: 0 },
        Memory {
            bytes: vec![0; 65536],
            writes: 0,
        },
        region(),
        binding(),
        l(),
        r,
    )
}
#[test]
fn borrowed_owned_audit_native_hardlinks_positional_eof_and_refunds() {
    let r = r();
    let original = container();
    let e = open(original.clone(), &r).unwrap();
    assert!(e.audit().unwrap().is_clean());
    assert_eq!(e.state(), ExtEditState::Ready);
    let a = e
        .open_file(&[NativeName::Bytes(vec![b'x', 255])], &r)
        .unwrap();
    let b = e
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    assert_eq!(a.identity(), b.identity());
    assert_eq!(a.len(), 1024);
    let mut out = [0; 17];
    assert_eq!(e.read_at(&a, 1019, &mut out, &r).unwrap(), 5);
    assert_eq!(&out[..5], &[73; 5]);
    assert_eq!(e.read_at(&a, 1024, &mut out, &r).unwrap(), 0);
    let other = open(container(), &r).unwrap();
    assert_eq!(
        other.read_at(&a, 0, &mut out, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    drop(other);
    drop((a, b));
    let (target, journal, state) = e.into_stores();
    assert_eq!(state, ExtEditState::Ready);
    assert_eq!(target.bytes, original);
    assert_eq!(target.writes + journal.writes, 0);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn dirty_ownership_budget_and_cancellation_never_authorize_storage() {
    let r = r();
    let mut dirty = container();
    dirty[BASE + 1024 + 58] = 0;
    assert_eq!(open(dirty, &r).err().unwrap().kind, ErrorKind::Unsupported);
    assert_eq!(r.memory.used(), 0);
    let mut lost = container();
    lost[BASE + 3073] |= 1;
    assert_eq!(open(lost, &r).err().unwrap().kind, ErrorKind::InvalidData);
    assert_eq!(r.memory.used(), 0);
    let small = Resources {
        memory: Budget::new(1024),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        open(container(), &small).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(small.memory.used(), 0);
    r.cancellation.cancel();
    assert_eq!(
        open(container(), &r).err().unwrap().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn recoverable_range_hardlink_overlap_generation_and_native_metadata_exact() {
    use partmgr::fs_ext_edit::ExtReplacement;
    let r = r();
    let before = container();
    let mut e = open(before.clone(), &r).unwrap();
    let a = e
        .open_file(&[NativeName::Bytes(vec![b'x', 255])], &r)
        .unwrap();
    let b = e
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    assert_eq!(
        e.plan_replace(
            &[
                ExtReplacement {
                    file: &a,
                    offset: 17,
                    bytes: b"new bytes"
                },
                ExtReplacement {
                    file: &b,
                    offset: 20,
                    bytes: b"overlap"
                }
            ],
            &r
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::InvalidOperation
    );
    let batch = e
        .plan_replace(
            &[ExtReplacement {
                file: &a,
                offset: 17,
                bytes: b"new bytes",
            }],
            &r,
        )
        .unwrap();
    let mut after = before.clone();
    for patch in batch.patches() {
        let at = BASE + patch.offset() as usize;
        assert_eq!(&before[at..at + patch.expected().len()], patch.expected());
        after[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
    }
    e.commit(batch, [9; 16], &r).unwrap();
    assert_eq!(e.generation(), 1);
    assert!(e.audit().unwrap().is_clean());
    assert_eq!(
        e.read_at(&a, 0, &mut [0; 1], &r).err().unwrap().kind,
        ErrorKind::StalePlan
    );
    drop((a, b));
    let file = e
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let mut out = [0; 9];
    assert_eq!(e.read_at(&file, 17, &mut out, &r).unwrap(), 9);
    assert_eq!(&out, b"new bytes");
    drop(file);
    let (target, journal, state) = e.into_stores();
    assert_eq!(state, ExtEditState::Ready);
    assert_eq!(target.bytes, after);
    assert_eq!(&target.bytes[BASE + 1024 + 58..BASE + 1024 + 60], &[1, 0]);
    assert!(journal.writes > 0);
    assert_eq!(r.memory.used(), 0);
}

use std::sync::{Arc, Mutex};
#[derive(Default)]
struct Clock {
    events: usize,
    fail: Option<usize>,
}
struct Model {
    bytes: Vec<u8>,
    durable: Vec<u8>,
    clock: Arc<Mutex<Clock>>,
    writes: usize,
}
impl Model {
    fn new(bytes: Vec<u8>, clock: Arc<Mutex<Clock>>) -> Self {
        Self {
            durable: bytes.clone(),
            bytes,
            clock,
            writes: 0,
        }
    }
    fn event(&self) -> bool {
        let mut c = self.clock.lock().unwrap();
        c.events += 1;
        c.fail == Some(c.events)
    }
    fn crash(&mut self, retain: bool) {
        if retain {
            self.durable.clone_from(&self.bytes);
        }
        self.bytes.clone_from(&self.durable);
    }
}
impl Storage for Model {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(at).map_err(io::Error::other)?;
        let end = at
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(
            self.bytes
                .get(at..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        let fail = self.event();
        let n = if fail {
            bytes.len().div_ceil(2)
        } else {
            bytes.len()
        };
        let at = usize::try_from(at).map_err(io::Error::other)?;
        self.bytes
            .get_mut(at..at + n)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(&bytes[..n]);
        if fail {
            Err(io::Error::other("modeled torn write"))
        } else {
            Ok(n)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.event() {
            return Err(io::Error::other("modeled failed barrier"));
        }
        self.durable.clone_from(&self.bytes);
        Ok(())
    }
}
fn fault_open(bytes: Vec<u8>, clock: Arc<Mutex<Clock>>, r: &Resources) -> ExtEditor<Model, Model> {
    ExtEditor::open(
        Model::new(bytes, clock.clone()),
        Model::new(vec![0; 65536], clock),
        region(),
        binding(),
        l(),
        r,
    )
    .unwrap()
}
#[test]
fn all_range_writes_barriers_torn_prefix_and_two_restart_models() {
    use partmgr::{
        fs_ext_edit::ExtReplacement,
        fs_undo::{self, UndoBinding, UndoState},
    };
    let r = r();
    let before = container();
    let clock = Arc::new(Mutex::new(Clock::default()));
    let mut e = fault_open(before.clone(), clock.clone(), &r);
    let file = e
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let batch = e
        .plan_replace(
            &[ExtReplacement {
                file: &file,
                offset: 13,
                bytes: &[0x42; 700],
            }],
            &r,
        )
        .unwrap();
    let mut after = before.clone();
    for patch in batch.patches() {
        let at = BASE + patch.offset() as usize;
        after[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
    }
    drop(file);
    e.commit(batch, [9; 16], &r).unwrap();
    let events = clock.lock().unwrap().events;
    drop(e);
    for restart in [None, Some(false), Some(true)] {
        for cut in 1..=events {
            let clock = Arc::new(Mutex::new(Clock {
                events: 0,
                fail: Some(cut),
            }));
            let mut e = fault_open(before.clone(), clock.clone(), &r);
            let file = e
                .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
                .unwrap();
            let batch = e
                .plan_replace(
                    &[ExtReplacement {
                        file: &file,
                        offset: 13,
                        bytes: &[0x42; 700],
                    }],
                    &r,
                )
                .unwrap();
            drop(file);
            e.commit(batch, [9; 16], &r).unwrap_err();
            assert_eq!(e.state(), ExtEditState::NeedsRecovery);
            assert!(
                e.open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
                    .is_err()
            );
            clock.lock().unwrap().fail = None;
            let (target, state, committed) = if let Some(retain) = restart {
                let (mut target, mut journal, _) = e.into_stores();
                target.crash(retain);
                journal.crash(retain);
                let Ok(status) = fs_undo::inspect(&journal, &r) else {
                    assert_eq!(target.bytes, before);
                    assert!(
                        ExtEditor::recover_open(
                            target,
                            journal,
                            region(),
                            UndoBinding {
                                volume: binding().volume,
                                generation: binding().generation,
                                transaction: [9; 16]
                            },
                            l(),
                            &r
                        )
                        .is_err()
                    );
                    assert_eq!(r.memory.used(), 0);
                    continue;
                };
                let e = ExtEditor::recover_open(
                    target,
                    journal,
                    region(),
                    UndoBinding {
                        volume: binding().volume,
                        generation: binding().generation,
                        transaction: [9; 16],
                    },
                    l(),
                    &r,
                )
                .unwrap();
                let (target, _, state) = e.into_stores();
                (target, state, status.state == UndoState::Committed)
            } else {
                let status = e.recover(&r).unwrap();
                let (target, _, state) = e.into_stores();
                (target, state, status.state == UndoState::Committed)
            };
            assert_eq!(state, ExtEditState::Ready);
            assert_eq!(
                target.bytes,
                if committed {
                    after.clone()
                } else {
                    before.clone()
                },
                "cut{cut} restart{restart:?}"
            );
            assert_eq!(r.memory.used(), 0);
        }
    }
}
struct Append {
    id: partmgr::fs_core::ObjectId,
    bytes: Vec<u8>,
    limit: usize,
}
impl partmgr::fs_core::FileRead for Append {
    fn identity(&self) -> &partmgr::fs_core::ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> partmgr::fs_core::Result<usize> {
        r.cancellation.check()?;
        let start = usize::try_from(at).unwrap_or(usize::MAX);
        let n = out
            .len()
            .min(self.limit)
            .min(self.bytes.len().saturating_sub(start));
        if n > 0 {
            out[..n].copy_from_slice(&self.bytes[start..start + n]);
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        _: &Resources,
        _: &mut dyn FnMut(partmgr::fs_core::LogicalExtent) -> partmgr::fs_core::Result<()>,
    ) -> partmgr::fs_core::Result<()> {
        Ok(())
    }
}
fn append(bytes: Vec<u8>) -> Append {
    Append {
        id: partmgr::fs_core::ObjectId {
            source: 999,
            generation: 7,
            native: vec![9],
        },
        bytes,
        limit: 13,
    }
}
fn larger_limits() -> ExtEditLimits {
    let mut limits = l();
    limits.affected_bytes = 32768;
    limits.audit.directory_blocks = 8;
    limits.undo.body_bytes = 65536;
    limits.work = 65536;
    limits
}
fn big_r() -> Resources {
    Resources {
        memory: Budget::new(16 << 20),
        cancellation: Cancellation::default(),
    }
}
#[test]
fn extend_crosses_indirect_truncate_zero_reallocate_and_exact_native_fields() {
    let r = big_r();
    let mut e = ExtEditor::open(
        Memory {
            bytes: container(),
            writes: 0,
        },
        Memory {
            bytes: vec![0; 131072],
            writes: 0,
        },
        region(),
        binding(),
        larger_limits(),
        &r,
    )
    .unwrap();
    let input = append((0..13 * 1024 + 7).map(|i| (i * 17) as u8).collect());
    let file = e
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let metadata = *file.inode().raw_metadata();
    let batch = e.plan_extend(&file, &input, &r).unwrap();
    assert_eq!(batch.resize_report().unwrap().allocated_data_blocks, 14);
    assert_eq!(batch.resize_report().unwrap().allocated_indirect_blocks, 1);
    e.commit(batch, [10; 16], &r).unwrap();
    drop(file);
    let file = e
        .open_file(&[NativeName::Bytes(vec![b'x', 255])], &r)
        .unwrap();
    assert_eq!(file.len(), 1024 + input.bytes.len() as u64);
    let mut out = vec![0; file.len() as usize];
    assert_eq!(e.read_at(&file, 0, &mut out, &r).unwrap(), out.len());
    assert_eq!(&out[..1024], &[73; 1024]);
    assert_eq!(&out[1024..], input.bytes);
    for (a, b) in [(0, 4), (8, 28), (32, 40), (100, 128)] {
        assert_eq!(&file.inode().raw_metadata()[a..b], &metadata[a..b]);
    }
    let batch = e.plan_truncate(&file, 513, &r).unwrap();
    assert_eq!(batch.resize_report().unwrap().freed_data_blocks, 14);
    assert_eq!(batch.resize_report().unwrap().freed_indirect_blocks, 1);
    e.commit(batch, [11; 16], &r).unwrap();
    drop(file);
    let file = e
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    assert_eq!(file.len(), 513);
    let batch = e.plan_truncate(&file, 0, &r).unwrap();
    assert_eq!(batch.resize_report().unwrap().freed_data_blocks, 1);
    e.commit(batch, [12; 16], &r).unwrap();
    drop(file);
    let file = e
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    assert!(file.is_empty());
    let batch = e.plan_extend(&file, &append(vec![0x42; 700]), &r).unwrap();
    e.commit(batch, [13; 16], &r).unwrap();
    drop(file);
    let file = e
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let mut out = [0; 700];
    assert_eq!(e.read_at(&file, 0, &mut out, &r).unwrap(), 700);
    assert_eq!(out, [0x42; 700]);
    drop(file);
    drop(e);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn namespace_native_metadata_bytes_move_hardlinks_delete_and_generations() {
    use partmgr::fs_ext_edit::{ExtCreateMetadata, ExtNamespaceOperation};
    let r = big_r();
    let mut e = ExtEditor::open(
        Memory {
            bytes: container(),
            writes: 0,
        },
        Memory {
            bytes: vec![0; 131072],
            writes: 0,
        },
        region(),
        binding(),
        larger_limits(),
        &r,
    )
    .unwrap();
    let root = e.open_directory(&[], &r).unwrap();
    let mut meta = ExtCreateMetadata::zeroed(0o100640);
    meta.raw[2..4].copy_from_slice(&1234u16.to_le_bytes());
    meta.raw[120..122].copy_from_slice(&5u16.to_le_bytes());
    for at in [8, 12, 16] {
        meta.raw[at..at + 4].copy_from_slice(&1_700_000_000u32.to_le_bytes());
    }
    let batch = e
        .plan_create_file(&root, &[b'n', 255], &meta, &[0x42; 700], &r)
        .unwrap();
    assert_eq!(
        batch.namespace_report().unwrap().operation,
        ExtNamespaceOperation::CreateFile
    );
    assert_eq!(
        batch.namespace_report().unwrap().assigned_inode_generation,
        Some(1)
    );
    e.commit(batch, [14; 16], &r).unwrap();
    assert_eq!(
        e.plan_create_directory(&root, b"old", &ExtCreateMetadata::zeroed(0o40750), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::StalePlan
    );
    drop(root);
    let file = e
        .open_file(&[NativeName::Bytes(vec![b'n', 255])], &r)
        .unwrap();
    assert_eq!(file.inode().uid(), (5u32 << 16) | 1234);
    assert_eq!(file.inode().mode(), 0o100640);
    assert_eq!(&file.inode().raw_metadata()[8..20], &meta.raw[8..20]);
    let mut payload = [0; 700];
    assert_eq!(e.read_at(&file, 0, &mut payload, &r).unwrap(), 700);
    assert_eq!(payload, [0x42; 700]);
    drop(file);
    let root = e.open_directory(&[], &r).unwrap();
    e.commit(
        e.plan_create_directory(&root, b"parent", &ExtCreateMetadata::zeroed(0o40750), &r)
            .unwrap(),
        [15; 16],
        &r,
    )
    .unwrap();
    drop(root);
    let root = e.open_directory(&[], &r).unwrap();
    let parent = e
        .open_directory(&[NativeName::Bytes(b"parent".to_vec())], &r)
        .unwrap();
    e.commit(
        e.plan_rename(&root, &[b'n', 255], &parent, b"moved bytes", &r)
            .unwrap(),
        [16; 16],
        &r,
    )
    .unwrap();
    drop((root, parent));
    let root = e.open_directory(&[], &r).unwrap();
    assert!(
        !e.plan_delete(&root, b"alias", 1_700_000_001, &r)
            .unwrap()
            .namespace_report()
            .unwrap()
            .released_inode
    );
    e.commit(
        e.plan_delete(&root, b"alias", 1_700_000_001, &r).unwrap(),
        [17; 16],
        &r,
    )
    .unwrap();
    drop(root);
    let file = e
        .open_file(&[NativeName::Bytes(vec![b'x', 255])], &r)
        .unwrap();
    assert_eq!(
        u16::from_le_bytes(file.inode().raw_metadata()[26..28].try_into().unwrap()),
        1
    );
    drop(file);
    let root = e.open_directory(&[], &r).unwrap();
    assert!(e.plan_delete(&root, b"parent", 1_700_000_002, &r).is_err());
    drop(root);
    let parent = e
        .open_directory(&[NativeName::Bytes(b"parent".to_vec())], &r)
        .unwrap();
    e.commit(
        e.plan_delete(&parent, b"moved bytes", 1_700_000_003, &r)
            .unwrap(),
        [18; 16],
        &r,
    )
    .unwrap();
    drop(parent);
    let root = e.open_directory(&[], &r).unwrap();
    e.commit(
        e.plan_delete(&root, b"parent", 1_700_000_004, &r).unwrap(),
        [19; 16],
        &r,
    )
    .unwrap();
    drop(root);
    assert_eq!(e.audit().unwrap().allocated_inodes(), 2);
    drop(e);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn sparse_replacement_allocates_zero_initialized_block_and_preserves_hardlinks() {
    use partmgr::fs_ext_edit::ExtReplacement;
    let r = big_r();
    let mut before = container();
    // Independently remove the single data allocation, retaining its logical hole.
    before[BASE + 3072] &= !(1 << 7);
    for at in [BASE + 1036, BASE + 2060] {
        if at == BASE + 1036 {
            before[at..at + 4].copy_from_slice(&56u32.to_le_bytes());
        } else {
            before[at..at + 2].copy_from_slice(&56u16.to_le_bytes());
        }
    }
    let inode = BASE + 5 * 1024 + 10 * 128;
    before[inode + 28..inode + 32].fill(0);
    before[inode + 40..inode + 44].fill(0);
    let mut e = ExtEditor::open(
        Memory {
            bytes: before.clone(),
            writes: 0,
        },
        Memory {
            bytes: vec![0; 131072],
            writes: 0,
        },
        region(),
        binding(),
        larger_limits(),
        &r,
    )
    .unwrap();
    let a = e
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let b = e
        .open_file(&[NativeName::Bytes(vec![b'x', 255])], &r)
        .unwrap();
    let batch = e
        .plan_replace(
            &[
                ExtReplacement {
                    file: &a,
                    offset: 7,
                    bytes: b"first",
                },
                ExtReplacement {
                    file: &b,
                    offset: 1000,
                    bytes: b"second",
                },
            ],
            &r,
        )
        .unwrap();
    assert_eq!(
        batch
            .range_allocation_report()
            .unwrap()
            .allocated_data_blocks,
        1
    );
    let mut expected = before;
    for patch in batch.patches() {
        let at = BASE + patch.offset() as usize;
        expected[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
    }
    e.commit(batch, [22; 16], &r).unwrap();
    drop((a, b));
    let a = e
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let mut out = [0; 1024];
    assert_eq!(e.read_at(&a, 0, &mut out, &r).unwrap(), 1024);
    let mut wanted = [0; 1024];
    wanted[7..12].copy_from_slice(b"first");
    wanted[1000..1006].copy_from_slice(b"second");
    assert_eq!(out, wanted);
    assert_eq!(a.inode().raw_metadata()[28..32], 2u32.to_le_bytes());
    drop(a);
    let (target, _, state) = e.into_stores();
    assert_eq!(state, ExtEditState::Ready);
    assert_eq!(target.bytes, expected);
    assert_eq!(r.memory.used(), 0);
}

fn namespace_fixture() -> Vec<u8> {
    let mut b = container();
    let w = |b: &mut [u8], at: usize, v: u16| {
        b[BASE + at..BASE + at + 2].copy_from_slice(&v.to_le_bytes())
    };
    let d = |b: &mut [u8], at: usize, v: u32| {
        b[BASE + at..BASE + at + 4].copy_from_slice(&v.to_le_bytes())
    };
    // Three independently initialized ordinary directories, each one allocated block.
    b[BASE + 3073] |= 7;
    b[BASE + 4097] |= 0x38;
    d(&mut b, 1036, 52);
    d(&mut b, 1040, 2);
    w(&mut b, 2060, 52);
    w(&mut b, 2062, 2);
    w(&mut b, 2064, 4);
    w(&mut b, 5 * 1024 + 128 + 26, 5);
    for (number, block) in [(12, 9), (13, 10), (14, 11)] {
        let at = 5 * 1024 + (number - 1) * 128;
        w(&mut b, at, 0o40755);
        d(&mut b, at + 4, 1024);
        w(&mut b, at + 26, 2);
        d(&mut b, at + 28, 2);
        d(&mut b, at + 40, block as u32);
        for (offset, ino, len, name) in [
            (0, number as u32, 12, b".".as_slice()),
            (12, 2, 1012, b"..".as_slice()),
        ] {
            let row = block * 1024 + offset;
            d(&mut b, row, ino);
            w(&mut b, row + 4, len);
            b[BASE + row + 6] = name.len() as u8;
            b[BASE + row + 7] = 2;
            b[BASE + row + 8..BASE + row + 8 + name.len()].copy_from_slice(name);
        }
    }
    w(&mut b, 7 * 1024 + 40 + 4, 16);
    for (offset, number, len, name) in [
        (56, 12, 16, b"parent".as_slice()),
        (72, 13, 12, b"dest".as_slice()),
        (84, 14, 940, b"empty".as_slice()),
    ] {
        let row = 7 * 1024 + offset;
        d(&mut b, row, number);
        w(&mut b, row + 4, len);
        b[BASE + row + 6] = name.len() as u8;
        b[BASE + row + 7] = 2;
        b[BASE + row + 8..BASE + row + 8 + name.len()].copy_from_slice(name);
    }
    // A last-link regular file with its own data allocation.
    b[BASE + 3073] |= 8;
    b[BASE + 4097] |= 0x40;
    d(&mut b, 1036, 51);
    d(&mut b, 1040, 1);
    w(&mut b, 2060, 51);
    w(&mut b, 2062, 1);
    let at = 5 * 1024 + 14 * 128;
    w(&mut b, at, 0o100640);
    d(&mut b, at + 4, 700);
    w(&mut b, at + 26, 1);
    d(&mut b, at + 28, 2);
    d(&mut b, at + 40, 12);
    b[BASE + 12288..BASE + 12988].fill(0x47);
    w(&mut b, 7 * 1024 + 84 + 4, 16);
    let row = 7 * 1024 + 100;
    d(&mut b, row, 15);
    w(&mut b, row + 4, 924);
    b[BASE + row + 6] = 6;
    b[BASE + row + 7] = 1;
    b[BASE + row + 8..BASE + row + 14].copy_from_slice(b"single");
    b
}
fn operation<S: Storage, J: Storage>(
    e: &ExtEditor<S, J>,
    action: usize,
    r: &Resources,
) -> partmgr::fs_core::Result<partmgr::fs_ext_edit::ExtEditBatch> {
    use partmgr::fs_ext_edit::ExtCreateMetadata;
    let root = e.open_directory(&[], r)?;
    match action {
        0 => e.plan_create_file(
            &root,
            b"new",
            &ExtCreateMetadata::zeroed(0o100640),
            &[0x42; 1400],
            r,
        ),
        1 => e.plan_create_directory(&root, b"newdir", &ExtCreateMetadata::zeroed(0o40750), r),
        2 => e.plan_rename(&root, b"alias", &root, b"longer renamed file", r),
        3 => {
            let dest = e.open_directory(&[NativeName::Bytes(b"dest".to_vec())], r)?;
            e.plan_rename(&root, b"parent", &dest, b"moved", r)
        }
        4 => e.plan_delete(&root, b"alias", 1_700_000_000, r),
        5 => e.plan_delete(&root, b"empty", 1_700_000_000, r),
        6 => {
            let file = e.open_file(&[NativeName::Bytes(b"alias".to_vec())], r)?;
            e.plan_extend(&file, &append(vec![0x42; 1400]), r)
        }
        7 => {
            let file = e.open_file(&[NativeName::Bytes(b"alias".to_vec())], r)?;
            e.plan_truncate(&file, 0, r)
        }
        8 => e.plan_delete(&root, b"single", 1_700_000_000, r),
        9 => {
            let file = e.open_file(&[NativeName::Bytes(b"alias".to_vec())], r)?;
            e.plan_replace(
                &[partmgr::fs_ext_edit::ExtReplacement {
                    file: &file,
                    offset: 17,
                    bytes: &[0x42; 700],
                }],
                r,
            )
        }
        10 => {
            let file = e.open_file(&[NativeName::Bytes(b"alias".to_vec())], r)?;
            e.plan_truncate(&file, 513, r)
        }
        11 => {
            let file = e.open_file(&[NativeName::Bytes(b"sparse".to_vec())], r)?;
            e.plan_replace(
                &[partmgr::fs_ext_edit::ExtReplacement {
                    file: &file,
                    offset: 17,
                    bytes: &[0x42; 700],
                }],
                r,
            )
        }
        12 => {
            let parent = e.open_directory(&[NativeName::Bytes(b"parent".to_vec())], r)?;
            e.plan_create_file(
                &parent,
                &[b'z'; 255],
                &ExtCreateMetadata::zeroed(0o100640),
                &[0x42; 1400],
                r,
            )
        }
        _ => unreachable!(),
    }
}
#[test]
fn namespace_allocation_all_writes_barriers_torn_prefix_and_restart_models() {
    use partmgr::fs_undo::{self, UndoBinding, UndoState};
    let r = big_r();
    let before = namespace_fixture();
    for action in 0..11 {
        let open = |clock: Arc<Mutex<Clock>>| {
            ExtEditor::open(
                Model::new(before.clone(), clock.clone()),
                Model::new(vec![0; 131072], clock),
                region(),
                binding(),
                larger_limits(),
                &r,
            )
            .unwrap()
        };
        let clock = Arc::new(Mutex::new(Clock::default()));
        let mut e = open(clock.clone());
        let batch = operation(&e, action, &r).unwrap();
        let mut after = before.clone();
        for patch in batch.patches() {
            let at = BASE + patch.offset() as usize;
            after[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
        }
        e.commit(batch, [23; 16], &r).unwrap();
        let events = clock.lock().unwrap().events;
        drop(e);
        for restart in [None, Some(false), Some(true)] {
            for cut in 1..=events {
                let clock = Arc::new(Mutex::new(Clock {
                    events: 0,
                    fail: Some(cut),
                }));
                let mut e = open(clock.clone());
                let batch = operation(&e, action, &r).unwrap();
                e.commit(batch, [23; 16], &r).unwrap_err();
                assert_eq!(e.state(), ExtEditState::NeedsRecovery);
                clock.lock().unwrap().fail = None;
                let (target, state, committed) = if let Some(retain) = restart {
                    let (mut target, mut journal, _) = e.into_stores();
                    target.crash(retain);
                    journal.crash(retain);
                    let Ok(status) = fs_undo::inspect(&journal, &r) else {
                        assert_eq!(target.bytes, before, "unpublished action{action} cut{cut}");
                        assert!(
                            ExtEditor::recover_open(
                                target,
                                journal,
                                region(),
                                UndoBinding {
                                    volume: binding().volume,
                                    generation: binding().generation,
                                    transaction: [23; 16],
                                },
                                larger_limits(),
                                &r
                            )
                            .is_err()
                        );
                        assert_eq!(r.memory.used(), 0);
                        continue;
                    };
                    let e = ExtEditor::recover_open(
                        target,
                        journal,
                        region(),
                        UndoBinding {
                            volume: binding().volume,
                            generation: binding().generation,
                            transaction: [23; 16],
                        },
                        larger_limits(),
                        &r,
                    )
                    .unwrap();
                    let (target, _, state) = e.into_stores();
                    (target, state, status.state == UndoState::Committed)
                } else {
                    let status = e.recover(&r).unwrap();
                    let (target, _, state) = e.into_stores();
                    (target, state, status.state == UndoState::Committed)
                };
                assert_eq!(state, ExtEditState::Ready);
                assert_eq!(
                    target.bytes,
                    if committed {
                        after.clone()
                    } else {
                        before.clone()
                    },
                    "action{action} cut{cut} restart{restart:?}"
                );
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn full_native_directory_growth_and_move_cycle_topology() {
    use partmgr::fs_ext_edit::ExtCreateMetadata;
    let r = big_r();
    let mut before = container();
    before[BASE + 7168 + 24..BASE + 8192].fill(0);
    for i in 0..3 {
        let at = BASE + 7168 + 24 + i * 264;
        before[at..at + 4].copy_from_slice(&11u32.to_le_bytes());
        let len = if i == 2 { 472u16 } else { 264u16 };
        before[at + 4..at + 6].copy_from_slice(&len.to_le_bytes());
        before[at + 6] = 255;
        before[at + 7] = 1;
        before[at + 8..at + 263].fill(b'a' + i as u8);
    }
    before[BASE + 6400 + 26..BASE + 6400 + 28].copy_from_slice(&3u16.to_le_bytes());
    let mut e = ExtEditor::open(
        Memory {
            bytes: before,
            writes: 0,
        },
        Memory {
            bytes: vec![0; 131072],
            writes: 0,
        },
        region(),
        binding(),
        larger_limits(),
        &r,
    )
    .unwrap();
    let root = e.open_directory(&[], &r).unwrap();
    let batch = e
        .plan_create_directory(&root, &[b'z'; 255], &ExtCreateMetadata::zeroed(0o40755), &r)
        .unwrap();
    e.commit(batch, [24; 16], &r).unwrap();
    drop(root);
    let root = e.open_directory(&[], &r).unwrap();
    assert_eq!(
        u32::from_le_bytes(root.inode().raw_metadata()[4..8].try_into().unwrap()),
        2048
    );
    let parent = e
        .open_directory(&[NativeName::Bytes(vec![b'z'; 255])], &r)
        .unwrap();
    e.commit(
        e.plan_create_directory(&parent, b"child", &ExtCreateMetadata::zeroed(0o40755), &r)
            .unwrap(),
        [25; 16],
        &r,
    )
    .unwrap();
    drop((root, parent));
    let root = e.open_directory(&[], &r).unwrap();
    let child = e
        .open_directory(
            &[
                NativeName::Bytes(vec![b'z'; 255]),
                NativeName::Bytes(b"child".to_vec()),
            ],
            &r,
        )
        .unwrap();
    assert_eq!(
        e.plan_rename(&root, &[b'z'; 255], &child, b"cycle", &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidOperation
    );
    assert!(
        e.plan_delete(&root, &[b'z'; 255], 1_700_000_000, &r)
            .is_err()
    );
    drop((root, child, e));
    assert_eq!(r.memory.used(), 0);
}

#[test]
#[ignore = "mandatory native gate: PARTMGR_EXT_EDIT_EVIDENCE, mke2fs, debugfs, e2fsck"]
fn native_ext2_all_operations_every_io_cut() {
    use partmgr::fs_undo::{self, UndoBinding, UndoState};
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf, process::Command};
    let out = PathBuf::from(
        std::env::var_os("PARTMGR_EXT_EDIT_EVIDENCE")
            .expect("enabled native gate requires evidence destination"),
    );
    assert!(out.is_absolute());
    fs::create_dir(&out).expect("fresh evidence destination required");
    let mut receipt = String::from(
        "profile=classic ext2 owned editing; injected regular-file IO; not physical power-loss evidence\nsource_capture=gate-start\n",
    );
    for source in [
        "src/fs_ext.rs",
        "src/fs_ext_audit.rs",
        "src/fs_ext_edit.rs",
        "src/fs_ext_edit_allocation.rs",
        "src/fs_ext_edit_namespace.rs",
        "src/fs_ext_edit_transaction.rs",
        "src/fs_undo.rs",
        "src/fs_core.rs",
        "src/fs_file.rs",
        "src/storage.rs",
        "tests/fs_ext_edit.rs",
        "tests/fixtures/ext2_clean.rs",
        "Cargo.lock",
    ] {
        let bytes = fs::read(source).unwrap();
        let archive = out.join("sources").join(source);
        fs::create_dir_all(archive.parent().unwrap()).unwrap();
        fs::write(&archive, &bytes).unwrap();
        fs::File::open(&archive).unwrap().sync_all().unwrap();
        receipt.push_str(&format!(
            "source={source} sha256={:x}\n",
            Sha256::digest(bytes)
        ));
    }
    let binary = fs::read(std::env::current_exe().unwrap()).unwrap();
    fs::write(out.join("gate-binary"), &binary).unwrap();
    fs::set_permissions(
        out.join("gate-binary"),
        fs::metadata(std::env::current_exe().unwrap())
            .unwrap()
            .permissions(),
    )
    .unwrap();
    receipt.push_str(&format!("binary_sha256={:x}\n", Sha256::digest(binary)));
    let mut tools = std::collections::BTreeMap::new();
    for tool in ["mke2fs", "debugfs", "e2fsck"] {
        let path = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
            .expect("enabled native gate requires all tools");
        receipt.push_str(&format!(
            "tool={tool} path={} sha256={:x}\n",
            path.display(),
            Sha256::digest(fs::read(&path).unwrap())
        ));
        tools.insert(tool, path);
    }
    let mut sequence = 0usize;
    let run = |tool: &str, args: Vec<String>, receipt: &mut String, sequence: &mut usize| {
        let result = Command::new(&tools[tool]).args(&args).output().unwrap();
        let prefix = format!("command-{:05}-{tool}", *sequence);
        *sequence += 1;
        fs::write(out.join(format!("{prefix}.stdout")), &result.stdout).unwrap();
        fs::write(out.join(format!("{prefix}.stderr")), &result.stderr).unwrap();
        receipt.push_str(&format!("command={} {args:?} status={} stdout={prefix}.stdout sha256={:x} stderr={prefix}.stderr sha256={:x}\n", tools[tool].display(), result.status, Sha256::digest(&result.stdout), Sha256::digest(&result.stderr)));
        assert!(
            result.status.success(),
            "{tool}: {} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    };
    for tool in ["mke2fs", "debugfs", "e2fsck"] {
        run(tool, vec!["-V".into()], &mut receipt, &mut sequence);
    }
    let payload: Vec<u8> = (0..131089)
        .map(|i| ((i * 37 + i / 19 + 11) % 251) as u8)
        .collect();
    let host = out.join("payload.bin");
    fs::write(&host, &payload).unwrap();
    receipt.push_str(&format!("payload_sha256={:x}\n", Sha256::digest(&payload)));
    let length = 16usize << 20;
    let mut limits = larger_limits();
    limits.audit.blocks = 16384;
    limits.audit.inodes = 8192;
    limits.audit.work = 8_000_000;
    limits.audit.directory_blocks = 128;
    limits.audit.directory_entries = 2048;
    limits.audit.findings = 64;
    limits.directory_entries = 2048;
    limits.file_blocks = 4096;
    limits.work = 500_000;
    limits.affected_bytes = 131072;
    limits.undo.patches = 512;
    limits.undo.body_bytes = 524288;
    let r = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let mut cases = 0;
    for block in [1024, 2048, 4096] {
        let seed_path = out.join(format!("ext2-{block}-seed.img"));
        fs::File::create(&seed_path)
            .unwrap()
            .set_len(length as u64)
            .unwrap();
        run(
            "mke2fs",
            vec![
                "-q".into(),
                "-F".into(),
                "-t".into(),
                "ext2".into(),
                "-b".into(),
                block.to_string(),
                "-I".into(),
                "128".into(),
                "-O".into(),
                "none,filetype,sparse_super".into(),
                seed_path.display().to_string(),
            ],
            &mut receipt,
            &mut sequence,
        );
        for command in [
            format!("write {} /alias", host.display()),
            "link /alias /other".into(),
            "set_inode_field /alias links_count 2".into(),
            "mkdir /parent".into(),
            "mkdir /dest".into(),
            "mkdir /empty".into(),
            format!("write {} /single", host.display()),
            format!("write {} /sparse", host.display()),
            "punch /sparse 0 999999".into(),
        ] {
            run(
                "debugfs",
                vec![
                    "-w".into(),
                    "-R".into(),
                    command,
                    seed_path.display().to_string(),
                ],
                &mut receipt,
                &mut sequence,
            );
        }
        for index in 0..(block as usize - 24) / 264 {
            let long = format!("{index:03}{}", "p".repeat(252));
            run(
                "debugfs",
                vec![
                    "-w".into(),
                    "-R".into(),
                    format!("link /alias /parent/{long}"),
                    seed_path.display().to_string(),
                ],
                &mut receipt,
                &mut sequence,
            );
        }
        run(
            "debugfs",
            vec![
                "-w".into(),
                "-R".into(),
                format!(
                    "set_inode_field /alias links_count {}",
                    2 + (block as usize - 24) / 264
                ),
                seed_path.display().to_string(),
            ],
            &mut receipt,
            &mut sequence,
        );
        run(
            "e2fsck",
            vec!["-fn".into(), seed_path.display().to_string()],
            &mut receipt,
            &mut sequence,
        );
        let image = fs::read(&seed_path).unwrap();
        receipt.push_str(&format!(
            "seed_block={block} sha256={:x}\n",
            Sha256::digest(&image)
        ));
        let mut before = vec![0xa5; BASE + length + BASE];
        before[BASE..BASE + length].copy_from_slice(&image);
        before[BASE + length..].fill(0x5a);
        let selected = ExtEditRegion {
            offset: BASE as u64,
            length: length as u64,
        };
        for action in 0..13 {
            let open = |clock: Arc<Mutex<Clock>>| {
                ExtEditor::open(
                    Model::new(before.clone(), clock.clone()),
                    Model::new(vec![0; 1 << 20], clock),
                    selected,
                    binding(),
                    limits,
                    &r,
                )
                .unwrap()
            };
            let clock = Arc::new(Mutex::new(Clock::default()));
            let mut e = open(clock.clone());
            let original_file = e
                .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
                .unwrap();
            let mut check = vec![0; payload.len()];
            assert_eq!(
                e.read_at(&original_file, 0, &mut check, &r).unwrap(),
                check.len()
            );
            assert_eq!(check, payload);
            drop(original_file);
            let batch = operation(&e, action, &r).unwrap();
            let mut after = before.clone();
            for patch in batch.patches() {
                let at = BASE + patch.offset() as usize;
                after[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
            }
            e.commit(batch, [23; 16], &r).unwrap();
            let events = clock.lock().unwrap().events;
            let (target, _, _) = e.into_stores();
            assert_eq!(target.bytes, after);
            let committed = out.join(format!("ext2-{block}-action-{action}-committed.img"));
            fs::write(&committed, &after[BASE..BASE + length]).unwrap();
            run(
                "e2fsck",
                vec!["-fn".into(), committed.display().to_string()],
                &mut receipt,
                &mut sequence,
            );
            let dump = out.join(format!("ext2-{block}-action-{action}-payload.bin"));
            let native_name = if action == 2 {
                "/longer renamed file"
            } else {
                "/other"
            };
            run(
                "debugfs",
                vec![
                    "-R".into(),
                    format!("dump \"{native_name}\" {}", dump.display()),
                    committed.display().to_string(),
                ],
                &mut receipt,
                &mut sequence,
            );
            let mut expected = payload.clone();
            if action == 6 {
                expected.extend_from_slice(&[0x42; 1400]);
            }
            if action == 7 {
                expected.clear();
            }
            if action == 9 {
                expected[17..717].fill(0x42);
            }
            if action == 10 {
                expected.truncate(513);
            }
            assert_eq!(fs::read(&dump).unwrap(), expected);
            if matches!(action, 11 | 12) {
                let extra = out.join(format!("ext2-{block}-action-{action}-extra.bin"));
                let name = if action == 11 {
                    "/sparse".to_string()
                } else {
                    format!("/parent/{}", "z".repeat(255))
                };
                run(
                    "debugfs",
                    vec![
                        "-R".into(),
                        format!("dump {name} {}", extra.display()),
                        committed.display().to_string(),
                    ],
                    &mut receipt,
                    &mut sequence,
                );
                let mut wanted = if action == 11 {
                    vec![0; payload.len()]
                } else {
                    vec![0x42; 1400]
                };
                if action == 11 {
                    wanted[17..717].fill(0x42);
                }
                assert_eq!(fs::read(&extra).unwrap(), wanted);
            }
            assert_eq!(fs::read(&committed).unwrap(), after[BASE..BASE + length]);
            receipt.push_str(&format!("normal block={block} action={action} events={events} image_sha256={:x} payload_sha256={:x}\n", Sha256::digest(&after[BASE..BASE + length]), Sha256::digest(&expected)));
            cases += 1;
            let mut prepared_cut = None;
            for restart in [None, Some(false), Some(true)] {
                for cut in 1..=events {
                    let clock = Arc::new(Mutex::new(Clock {
                        events: 0,
                        fail: Some(cut),
                    }));
                    let mut e = open(clock.clone());
                    let batch = operation(&e, action, &r).unwrap();
                    e.commit(batch, [23; 16], &r).unwrap_err();
                    clock.lock().unwrap().fail = None;
                    let (target, is_committed) = if let Some(retain) = restart {
                        let (mut target, mut journal, _) = e.into_stores();
                        target.crash(retain);
                        journal.crash(retain);
                        let Ok(status) = fs_undo::inspect(&journal, &r) else {
                            assert_eq!(target.bytes, before);
                            receipt.push_str(&format!("unpublished block={block} action={action} cut={cut} restart={restart:?} container_sha256={:x}\n", Sha256::digest(&target.bytes)));
                            cases += 1;
                            continue;
                        };
                        if action == 0
                            && status.state == UndoState::Prepared
                            && target.bytes != before
                        {
                            prepared_cut = Some(cut);
                        }
                        let e = ExtEditor::recover_open(
                            target,
                            journal,
                            selected,
                            UndoBinding {
                                volume: binding().volume,
                                generation: binding().generation,
                                transaction: [23; 16],
                            },
                            limits,
                            &r,
                        )
                        .unwrap();
                        let (target, _, state) = e.into_stores();
                        assert_eq!(state, ExtEditState::Ready);
                        (target, status.state == UndoState::Committed)
                    } else {
                        let status = e.recover(&r).unwrap();
                        let (target, _, state) = e.into_stores();
                        assert_eq!(state, ExtEditState::Ready);
                        (target, status.state == UndoState::Committed)
                    };
                    assert_eq!(
                        target.bytes,
                        if is_committed {
                            after.clone()
                        } else {
                            before.clone()
                        },
                        "block{block} action{action} cut{cut} restart{restart:?}"
                    );
                    let recovered = out.join("recovery-check.img");
                    fs::write(&recovered, &target.bytes[BASE..BASE + length]).unwrap();
                    run(
                        "e2fsck",
                        vec!["-fn".into(), recovered.display().to_string()],
                        &mut receipt,
                        &mut sequence,
                    );
                    assert_eq!(
                        fs::read(&recovered).unwrap(),
                        target.bytes[BASE..BASE + length]
                    );
                    receipt.push_str(&format!("recovery block={block} action={action} cut={cut} restart={restart:?} committed={is_committed} container_sha256={:x}\n", Sha256::digest(&target.bytes)));
                    assert_eq!(r.memory.used(), 0);
                    cases += 1;
                }
            }
            if action == 0 {
                let prepared_cut = prepared_cut.expect("native prepared namespace mutation");
                let prepare = || {
                    let clock = Arc::new(Mutex::new(Clock {
                        events: 0,
                        fail: Some(prepared_cut),
                    }));
                    let mut e = open(clock.clone());
                    e.commit(operation(&e, action, &r).unwrap(), [23; 16], &r)
                        .unwrap_err();
                    *clock.lock().unwrap() = Clock::default();
                    (e, clock)
                };
                let (mut e, clock) = prepare();
                e.recover(&r).unwrap();
                let recovery_events = clock.lock().unwrap().events;
                drop(e);
                for restart in [None, Some(false), Some(true)] {
                    for cut in 1..=recovery_events {
                        let (mut e, clock) = prepare();
                        clock.lock().unwrap().fail = Some(cut);
                        e.recover(&r).unwrap_err();
                        clock.lock().unwrap().fail = None;
                        let target = if let Some(retain) = restart {
                            let (mut target, mut journal, _) = e.into_stores();
                            target.crash(retain);
                            journal.crash(retain);
                            let e = ExtEditor::recover_open(
                                target,
                                journal,
                                selected,
                                UndoBinding {
                                    volume: binding().volume,
                                    generation: binding().generation,
                                    transaction: [23; 16],
                                },
                                limits,
                                &r,
                            )
                            .unwrap();
                            let (target, _, state) = e.into_stores();
                            assert_eq!(state, ExtEditState::Ready);
                            target
                        } else {
                            e.recover(&r).unwrap();
                            let (target, _, state) = e.into_stores();
                            assert_eq!(state, ExtEditState::Ready);
                            target
                        };
                        assert_eq!(
                            target.bytes, before,
                            "native recovery block{block} cut{cut} restart{restart:?}"
                        );
                        let recovered = out.join("recovery-check.img");
                        fs::write(&recovered, &target.bytes[BASE..BASE + length]).unwrap();
                        run(
                            "e2fsck",
                            vec!["-fn".into(), recovered.display().to_string()],
                            &mut receipt,
                            &mut sequence,
                        );
                        assert_eq!(
                            fs::read(&recovered).unwrap(),
                            target.bytes[BASE..BASE + length]
                        );
                        receipt.push_str(&format!("interrupted_recovery block={block} cut={cut} restart={restart:?} container_sha256={:x}\n", Sha256::digest(&target.bytes)));
                        assert_eq!(r.memory.used(), 0);
                        cases += 1;
                    }
                }
            }
            fs::write(out.join("receipt.txt"), &receipt).unwrap();
        }
    }
    for directory in ["src", "tests", "tests/fixtures"] {
        for entry in fs::read_dir(out.join("sources").join(directory)).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let relative = path.strip_prefix(out.join("sources")).unwrap();
                assert_eq!(
                    fs::read(&path).unwrap(),
                    fs::read(relative).unwrap(),
                    "source changed during native gate: {}",
                    relative.display()
                );
            }
        }
    }
    assert_eq!(
        fs::read(out.join("sources/Cargo.lock")).unwrap(),
        fs::read("Cargo.lock").unwrap()
    );
    receipt.push_str(&format!(
        "source_end_matches_start=true\ncases={cases}\nresult=pass\n"
    ));
    fs::write(out.join("receipt.txt"), &receipt).unwrap();
    for entry in fs::read_dir(&out).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            fs::File::open(path).unwrap().sync_all().unwrap();
        }
    }
    for directory in [
        "sources/src",
        "sources/tests/fixtures",
        "sources/tests",
        "sources",
    ] {
        fs::File::open(out.join(directory))
            .unwrap()
            .sync_all()
            .unwrap();
    }
    fs::File::open(&out).unwrap().sync_all().unwrap();
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn interrupted_namespace_rollback_every_write_barrier_and_restart() {
    use partmgr::fs_undo::{self, UndoBinding, UndoState};
    let r = big_r();
    let before = namespace_fixture();
    let open = |clock: Arc<Mutex<Clock>>| {
        ExtEditor::open(
            Model::new(before.clone(), clock.clone()),
            Model::new(vec![0; 131072], clock),
            region(),
            binding(),
            larger_limits(),
            &r,
        )
        .unwrap()
    };
    let clock = Arc::new(Mutex::new(Clock::default()));
    let mut normal = open(clock.clone());
    normal
        .commit(operation(&normal, 0, &r).unwrap(), [23; 16], &r)
        .unwrap();
    let events = clock.lock().unwrap().events;
    drop(normal);
    let mut prepared_cut = None;
    for cut in 1..=events {
        let clock = Arc::new(Mutex::new(Clock {
            events: 0,
            fail: Some(cut),
        }));
        let mut e = open(clock);
        e.commit(operation(&e, 0, &r).unwrap(), [23; 16], &r)
            .unwrap_err();
        let (target, journal, _) = e.into_stores();
        if fs_undo::inspect(&journal, &r).is_ok_and(|s| s.state == UndoState::Prepared)
            && target.bytes != before
        {
            prepared_cut = Some(cut);
        }
    }
    let prepared_cut = prepared_cut.expect("actual durable prepared namespace mutation");
    let prepare = || {
        let clock = Arc::new(Mutex::new(Clock {
            events: 0,
            fail: Some(prepared_cut),
        }));
        let mut e = open(clock.clone());
        e.commit(operation(&e, 0, &r).unwrap(), [23; 16], &r)
            .unwrap_err();
        *clock.lock().unwrap() = Clock::default();
        (e, clock)
    };
    let (mut e, clock) = prepare();
    assert_eq!(e.recover(&r).unwrap().state, UndoState::RolledBack);
    let recovery_events = clock.lock().unwrap().events;
    drop(e);
    for restart in [None, Some(false), Some(true)] {
        for cut in 1..=recovery_events {
            let (mut e, clock) = prepare();
            clock.lock().unwrap().fail = Some(cut);
            e.recover(&r).unwrap_err();
            assert_eq!(e.state(), ExtEditState::NeedsRecovery);
            clock.lock().unwrap().fail = None;
            let target = if let Some(retain) = restart {
                let (mut target, mut journal, _) = e.into_stores();
                target.crash(retain);
                journal.crash(retain);
                let e = ExtEditor::recover_open(
                    target,
                    journal,
                    region(),
                    UndoBinding {
                        volume: binding().volume,
                        generation: binding().generation,
                        transaction: [23; 16],
                    },
                    larger_limits(),
                    &r,
                )
                .unwrap();
                let (target, _, state) = e.into_stores();
                assert_eq!(state, ExtEditState::Ready);
                target
            } else {
                e.recover(&r).unwrap();
                let (target, _, state) = e.into_stores();
                assert_eq!(state, ExtEditState::Ready);
                target
            };
            assert_eq!(target.bytes, before, "recovery cut{cut} restart{restart:?}");
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn planning_capacity_invalid_metadata_names_and_cancellation_are_read_only() {
    use partmgr::fs_ext_edit::ExtCreateMetadata;
    let r = big_r();
    let before = namespace_fixture();
    let mut e = ExtEditor::open(
        Memory {
            bytes: before.clone(),
            writes: 0,
        },
        Memory {
            bytes: vec![0; 131072],
            writes: 0,
        },
        region(),
        binding(),
        larger_limits(),
        &r,
    )
    .unwrap();
    let root = e.open_directory(&[], &r).unwrap();
    for name in [
        b"".as_slice(),
        b".",
        b"..",
        b"bad/name",
        b"nul\0name",
        &[b'x'; 256],
    ] {
        assert!(
            e.plan_create_file(
                &root,
                name,
                &ExtCreateMetadata::zeroed(0o100644),
                b"payload",
                &r
            )
            .is_err()
        );
    }
    assert!(
        e.plan_create_file(
            &root,
            b"alias",
            &ExtCreateMetadata::zeroed(0o100644),
            b"payload",
            &r
        )
        .is_err()
    );
    let mut invalid = ExtCreateMetadata::zeroed(0o100644);
    invalid.raw[40..44].copy_from_slice(&8u32.to_le_bytes());
    assert!(
        e.plan_create_file(&root, b"new", &invalid, b"payload", &r)
            .is_err()
    );
    assert!(e.plan_delete(&root, b"single", 0, &r).is_err());
    assert_eq!(
        e.plan_create_file(
            &root,
            b"large",
            &ExtCreateMetadata::zeroed(0o100644),
            &[0; 40000],
            &r
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::BudgetExhausted
    );
    let batch = e
        .plan_create_file(
            &root,
            b"new",
            &ExtCreateMetadata::zeroed(0o100644),
            b"payload",
            &r,
        )
        .unwrap();
    r.cancellation.cancel();
    assert!(e.commit(batch, [26; 16], &r).is_err());
    assert_eq!(e.state(), ExtEditState::Ready);
    drop(root);
    let (target, journal, _) = e.into_stores();
    assert_eq!(target.bytes, before);
    assert_eq!(target.writes, 0);
    assert_eq!(journal.writes, 0);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn full_owned_allocation_rejects_extension_before_journal_or_target_writes() {
    let r = big_r();
    let mut before = container();
    before[BASE + 3072..BASE + 3080].fill(255);
    before[BASE + 1036..BASE + 1040].fill(0);
    before[BASE + 2060..BASE + 2062].fill(0);
    let inode = BASE + 6400;
    before[inode + 4..inode + 8].copy_from_slice(&(55u32 * 1024).to_le_bytes());
    before[inode + 28..inode + 32].copy_from_slice(&112u32.to_le_bytes());
    for i in 0..12 {
        before[inode + 40 + i * 4..inode + 44 + i * 4]
            .copy_from_slice(&(8u32 + i as u32).to_le_bytes());
    }
    before[inode + 88..inode + 92].copy_from_slice(&63u32.to_le_bytes());
    for i in 0..43 {
        let at = BASE + 63 * 1024 + i * 4;
        before[at..at + 4].copy_from_slice(&(20u32 + i as u32).to_le_bytes());
    }
    let mut limits = larger_limits();
    limits.file_blocks = 64;
    let e = ExtEditor::open(
        Memory {
            bytes: before.clone(),
            writes: 0,
        },
        Memory {
            bytes: vec![0; 131072],
            writes: 0,
        },
        region(),
        binding(),
        limits,
        &r,
    )
    .unwrap();
    let file = e
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    assert!(e.plan_extend(&file, &append(vec![0x42]), &r).is_err());
    drop(file);
    let (target, journal, state) = e.into_stores();
    assert_eq!(state, ExtEditState::Ready);
    assert_eq!(target.bytes, before);
    assert_eq!(target.writes, 0);
    assert_eq!(journal.writes, 0);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn deletion_time_orphan_domain_boundary_rejects_before_publication() {
    let r = big_r();
    let before = namespace_fixture();
    let inode_count = u32::from_le_bytes(before[BASE + 1024..BASE + 1028].try_into().unwrap());
    for time in [inode_count, 1_700_000_000] {
        let mut editor = ExtEditor::open(
            Memory {
                bytes: before.clone(),
                writes: 0,
            },
            Memory {
                bytes: vec![0; 131072],
                writes: 0,
            },
            region(),
            binding(),
            larger_limits(),
            &r,
        )
        .unwrap();
        let root = editor.open_directory(&[], &r).unwrap();
        for ambiguous in [1, inode_count - 1] {
            let error = match editor.plan_delete(&root, b"single", ambiguous, &r) {
                Err(error) => error,
                Ok(_) => panic!("accepted ambiguous orphan-domain deletion time"),
            };
            assert_eq!(error.kind, ErrorKind::Unsupported);
        }
        let file = editor
            .open_file(&[NativeName::Bytes(b"single".to_vec())], &r)
            .unwrap();
        let number = file.inode().number();
        let batch = editor.plan_delete(&root, b"single", time, &r).unwrap();
        assert_eq!(batch.namespace_report().unwrap().deletion_time, Some(time));
        editor.commit(batch, [0x61; 16], &r).unwrap();
        drop((file, root));
        let (target, journal, state) = editor.into_stores();
        assert_eq!(state, ExtEditState::Ready);
        let at = BASE + 5 * 1024 + (number as usize - 1) * 128 + 20;
        assert_eq!(
            u32::from_le_bytes(target.bytes[at..at + 4].try_into().unwrap()),
            time
        );
        assert!(target.writes > 0 && journal.writes > 0);
        assert_eq!(r.memory.used(), 0);
    }
}
