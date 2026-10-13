//! Independent native fixtures for planner-authored ordered data roles.
use super::transaction::{OrderedOperation, OrderedOrigin};
use super::*;
use crate::fs_core::{Budget, Cancellation, FileRead, LogicalExtent};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[derive(Clone)]
struct ProjectionProbe {
    armed: Arc<AtomicBool>,
    seen: Arc<AtomicBool>,
    cancel: Option<Cancellation>,
}

struct Memory {
    probe: Option<ProjectionProbe>,
    bytes: Vec<u8>,
    writes: usize,
}
impl Storage for Memory {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        if offset == 1024
            && out.len() == 1024
            && let Some(probe) = &self.probe
            && probe.armed.load(Ordering::SeqCst)
        {
            probe.seen.store(true, Ordering::SeqCst);
            if let Some(token) = &probe.cancel {
                token.cancel();
            }
        }
        let at = offset as usize;
        out.copy_from_slice(
            self.bytes
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        let at = offset as usize;
        self.bytes[at..at + bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn w16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
// A complete one-group ext2 image with a two-link regular inode, twelve direct
// blocks, and a partial final block. No builder or planner authors these bytes.
fn fixture(bs: usize) -> (Vec<u8>, usize) {
    let first = usize::from(bs == 1024);
    let blocks = first + 128;
    let bitmap = first + 2;
    let ibitmap = bitmap + 1;
    let table = bitmap + 2;
    let root_block = table + 2048usize.div_ceil(bs);
    let file_block = root_block + 1;
    let used = file_block + 12 - first;
    let free = 128 - used;
    let mut b = vec![0; blocks * bs];
    for (at, value) in [
        (0, 16),
        (4, blocks as u32),
        (12, free as u32),
        (16, 5),
        (20, first as u32),
        (24, (bs / 1024).trailing_zeros()),
        (28, (bs / 1024).trailing_zeros()),
        (32, 128),
        (36, 128),
        (40, 16),
        (76, 1),
        (84, 11),
        (96, 2),
    ] {
        w32(&mut b, 1024 + at, value);
    }
    for (at, value) in [(56, 0xef53), (58, 1), (88, 128)] {
        w16(&mut b, 1024 + at, value);
    }
    let gd = (first + 1) * bs;
    for (at, value) in [(0, bitmap), (4, ibitmap), (8, table)] {
        w32(&mut b, gd + at, value as u32);
    }
    for (at, value) in [(12, free as u16), (14, 5), (16, 1)] {
        w16(&mut b, gd + at, value);
    }
    b[bitmap * bs..(bitmap + 1) * bs].fill(255);
    for bit in used..128 {
        b[bitmap * bs + bit / 8] &= !(1 << (bit % 8));
    }
    b[ibitmap * bs..(ibitmap + 1) * bs].fill(255);
    for bit in 11..16 {
        b[ibitmap * bs + bit / 8] &= !(1 << (bit % 8));
    }
    let root = table * bs + 128;
    let file = table * bs + 1280;
    w16(&mut b, root, 0x41ed);
    w32(&mut b, root + 4, bs as u32);
    w16(&mut b, root + 26, 2);
    w32(&mut b, root + 28, (bs / 512) as u32);
    w32(&mut b, root + 40, root_block as u32);
    w16(&mut b, file, 0x81a4);
    w32(&mut b, file + 4, (12 * bs - 17) as u32);
    w16(&mut b, file + 26, 2);
    w32(&mut b, file + 28, (12 * bs / 512) as u32);
    w32(&mut b, file + 100, 0x137);
    for n in 0..12 {
        w32(&mut b, file + 40 + 4 * n, (file_block + n) as u32);
        b[(file_block + n) * bs..(file_block + n + 1) * bs].fill(73);
    }
    for (off, ino, len, name, kind) in [
        (0, 2, 12, b".".as_slice(), 2),
        (12, 2, 12, b"..".as_slice(), 2),
        (24, 11, 16, b"x".as_slice(), 1),
        (40, 11, bs - 40, b"alias".as_slice(), 1),
    ] {
        let at = root_block * bs + off;
        w32(&mut b, at, ino);
        w16(&mut b, at + 4, len as u16);
        b[at + 6] = name.len() as u8;
        b[at + 7] = kind;
        b[at + 8..at + 8 + name.len()].copy_from_slice(name);
    }
    (b, (file_block + 11) * bs)
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(16 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ExtEditLimits {
    ExtEditLimits {
        audit: ExtAuditLimits {
            blocks: 256,
            inodes: 16,
            work: 262144,
            directory_blocks: 8,
            directory_entries: 64,
            findings: 32,
        },
        file_blocks: 64,
        directory_entries: 64,
        affected_bytes: 131072,
        work: 20000,
        undo: UndoLimits {
            patches: 256,
            body_bytes: 262144,
        },
    }
}
fn open(bs: usize, r: &Resources) -> ExtEditor<Memory, Memory> {
    let (bytes, _) = fixture(bs);
    let length = bytes.len() as u64;
    ExtEditor::open(
        Memory {
            bytes,
            writes: 0,
            probe: None,
        },
        Memory {
            probe: None,
            bytes: vec![0; 524288],
            writes: 0,
        },
        ExtEditRegion { offset: 0, length },
        ExtEditBinding {
            volume: [3; 32],
            generation: 7,
        },
        limits(),
        r,
    )
    .unwrap()
}
struct Input {
    arm: Option<Arc<AtomicBool>>,
    id: ObjectId,
    length: u64,
}
impl FileRead for Input {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.length
    }
    fn read_at(&self, offset: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        let n = (self.length.saturating_sub(offset)).min(out.len() as u64) as usize;
        out[..n].fill(0x62);
        if let Some(arm) = &self.arm {
            arm.store(true, Ordering::SeqCst);
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        _: &Resources,
        _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        Ok(())
    }
}
fn input(length: usize) -> Input {
    Input {
        arm: None,
        id: ObjectId {
            source: 555,
            generation: 3,
            native: vec![9],
        },
        length: length as u64,
    }
}
#[test]
fn append_roles_distinguish_visible_tail_new_data_and_indirect_metadata_all_block_sizes() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let editor = open(bs, &r);
        let baseline = r.memory.used();
        let file = editor
            .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
            .unwrap();
        let batch = editor.plan_extend(&file, &input(bs + 64), &r).unwrap();
        let evidence = batch.ordered.as_ref().unwrap();
        assert_eq!(
            (evidence.source, evidence.generation),
            (batch.source, batch.generation)
        );
        assert!(
            matches!(evidence.operation,OrderedOperation::Extend { inode:11,old_length,new_length,.. } if old_length==(12*bs-17) as u64 && new_length==(13*bs+47) as u64)
        );
        assert_eq!(evidence.data.len(), 3);
        let tail = fixture(bs).1 as u64;
        assert_eq!(
            (
                evidence.data[0].offset,
                evidence.data[0].bytes,
                evidence.data[0].logical_block
            ),
            (tail + (bs - 17) as u64, 17, 11)
        );
        assert_eq!(
            evidence.data[0].origin,
            OrderedOrigin::ExistingAppendTail {
                visible_prefix_bytes: bs - 17
            }
        );
        for role in &evidence.data[1..] {
            assert_eq!(role.origin, OrderedOrigin::AuditedFree);
            assert_eq!(role.bytes, bs);
            assert_eq!(role.offset % bs as u64, 0);
        }
        assert_eq!(batch.resize_report().unwrap().allocated_indirect_blocks, 1);
        assert_eq!(
            evidence.data.iter().map(|d| d.bytes).sum::<usize>(),
            2 * bs + 17
        );
        for role in &evidence.data {
            assert!(
                batch
                    .patches()
                    .iter()
                    .any(|p| p.offset() == role.offset && p.replacement().len() == role.bytes)
            );
        }
        drop(batch);
        drop(file);
        assert_eq!(r.memory.used(), baseline);
        let (target, journal, _) = editor.into_stores();
        assert_eq!((target.writes, journal.writes), (0, 0));
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn regular_creation_has_data_roles_but_directory_initialization_stays_metadata() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let editor = open(bs, &r);
        let dir = editor.open_directory(&[], &r).unwrap();
        let payload = vec![0x34; bs + 3];
        let file = editor
            .plan_create_file(
                &dir,
                b"new",
                &ExtCreateMetadata::zeroed(0x81a4),
                &payload,
                &r,
            )
            .unwrap();
        let evidence = file.ordered.as_ref().unwrap();
        assert!(
            matches!(evidence.operation,OrderedOperation::Create { length,.. } if length==(bs+3) as u64)
        );
        assert_eq!(evidence.data.len(), 2);
        assert!(
            evidence
                .data
                .iter()
                .all(|p| p.origin == OrderedOrigin::AuditedFree && p.bytes == bs)
        );
        let empty = editor
            .plan_create_file(&dir, b"empty", &ExtCreateMetadata::zeroed(0x81a4), &[], &r)
            .unwrap();
        assert!(empty.ordered.as_ref().unwrap().data.is_empty());
        let directory = editor
            .plan_create_directory(&dir, b"dir", &ExtCreateMetadata::zeroed(0x41ed), &r)
            .unwrap();
        assert!(directory.ordered.is_none());
        drop((directory, empty, file, dir));
        drop(editor);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn unqualified_operations_and_equal_binding_foreign_handles_cannot_mint_roles() {
    let r = resources();
    let editor = open(1024, &r);
    let other = open(1024, &r);
    let file = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let foreign = other
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    assert_ne!(file.identity().source, foreign.identity().source);
    let error = editor.plan_extend(&foreign, &input(1), &r).err().unwrap();
    assert_eq!(error.kind, ErrorKind::StalePlan);
    let replace = editor
        .plan_replace(
            &[ExtReplacement {
                file: &file,
                offset: 0,
                bytes: b"z",
            }],
            &r,
        )
        .unwrap();
    assert!(replace.ordered.is_none());
    let truncate = editor.plan_truncate(&file, 1024, &r).unwrap();
    assert!(truncate.ordered.is_none());
    drop((replace, truncate, file, foreign, editor, other));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn failed_role_planning_refunds_leases_and_never_writes() {
    let r = resources();
    let mut editor = open(1024, &r);
    let file = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let baseline = r.memory.used();
    editor.limits.affected_bytes = 16;
    let error = editor.plan_extend(&file, &input(2048), &r).err().unwrap();
    assert_eq!(error.kind, ErrorKind::BudgetExhausted);
    assert_eq!(r.memory.used(), baseline);
    editor.limits = limits();
    editor.limits.work = 1;
    let error = editor.plan_extend(&file, &input(2048), &r).err().unwrap();
    assert_eq!(error.kind, ErrorKind::BudgetExhausted);
    assert_eq!(r.memory.used(), baseline);
    drop(file);
    let (target, journal, _) = editor.into_stores();
    assert_eq!((target.writes, journal.writes), (0, 0));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn fresh_data_token_cannot_cross_planners_with_identical_source_and_generation() {
    let r = resources();
    let editor = open(1024, &r);
    let file = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let batch = editor.plan_extend(&file, &input(32), &r).unwrap();
    let operation = batch.ordered.as_ref().unwrap().operation;
    drop(batch);
    let context = editor.planning_context(&r).unwrap();
    let baseline = r.memory.used();
    let mut first = allocation::Planner::new(&context, &r).unwrap();
    let mut second = allocation::Planner::new(&context, &r).unwrap();
    first.begin_ordered(operation).unwrap();
    second.begin_ordered(operation).unwrap();
    let token = first.allocate_regular(12).unwrap();
    let error = second
        .patch_regular_fresh(token, vec![0; 1024])
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidOperation);
    drop((first, second));
    assert_eq!(r.memory.used(), baseline);
    drop(file);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn append_old_tail_only_and_aligned_eof_have_exact_distinct_roles() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let editor = open(bs, &r);
        let file = editor
            .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
            .unwrap();
        let batch = editor.plan_extend(&file, &input(3), &r).unwrap();
        let roles = &batch.ordered.as_ref().unwrap().data;
        assert_eq!(roles.len(), 1);
        assert_eq!(
            roles[0].origin,
            OrderedOrigin::ExistingAppendTail {
                visible_prefix_bytes: bs - 17
            }
        );
        assert_eq!(roles[0].bytes, 17);
        assert_eq!(batch.resize_report().unwrap().allocated_data_blocks, 0);
        drop((batch, file, editor));
        assert_eq!(r.memory.used(), 0);

        let mut editor = open(bs, &r);
        let first = usize::from(bs == 1024);
        let table = first + 4;
        w32(
            &mut editor.target.storage.bytes,
            table * bs + 1280 + 4,
            (12 * bs) as u32,
        );
        // Reopen after changing the fixture so admission and handles see this EOF.
        let (target, journal, _) = editor.into_stores();
        let editor = ExtEditor::open(
            target,
            journal,
            ExtEditRegion {
                offset: 0,
                length: ((first + 128) * bs) as u64,
            },
            ExtEditBinding {
                volume: [3; 32],
                generation: 7,
            },
            limits(),
            &r,
        )
        .unwrap();
        let file = editor
            .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
            .unwrap();
        let batch = editor.plan_extend(&file, &input(1), &r).unwrap();
        let roles = &batch.ordered.as_ref().unwrap().data;
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].origin, OrderedOrigin::AuditedFree);
        assert_eq!((roles[0].logical_block, roles[0].bytes), (12, bs));
        assert_eq!(batch.resize_report().unwrap().allocated_indirect_blocks, 1);
        drop((batch, file, editor));
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn cancellation_from_projected_source_read_refunds_and_preserves_all_native_bytes() {
    let r = resources();
    let mut editor = open(1024, &r);
    let file = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let baseline = r.memory.used();
    let original = editor.target.storage.bytes.clone();
    let probe = ProjectionProbe {
        armed: Arc::new(AtomicBool::new(false)),
        seen: Arc::new(AtomicBool::new(false)),
        cancel: Some(r.cancellation.clone()),
    };
    editor.target.storage.probe = Some(probe.clone());
    let mut input = input(3);
    input.arm = Some(probe.armed.clone());
    let error = editor.plan_extend(&file, &input, &r).err().unwrap();
    assert!(probe.seen.load(Ordering::SeqCst));
    assert_eq!(error.kind, ErrorKind::Cancelled);
    assert_eq!(r.memory.used(), baseline);
    assert_eq!(editor.target.storage.bytes, original);
    drop(file);
    let (target, journal, _) = editor.into_stores();
    assert_eq!((target.writes, journal.writes), (0, 0));
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn extending_empty_existing_inode_only_admits_new_regular_data() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let editor = open(bs, &r);
        let (mut target, journal, _) = editor.into_stores();
        let first = usize::from(bs == 1024);
        let bitmap = first + 2;
        let table = first + 4;
        let file = table * bs + 1280;
        let start =
            u32::from_le_bytes(target.bytes[file + 40..file + 44].try_into().unwrap()) as usize;
        w32(&mut target.bytes, file + 4, 0);
        w32(&mut target.bytes, file + 28, 0);
        target.bytes[file + 40..file + 100].fill(0);
        for block in start..start + 12 {
            let bit = block - first;
            target.bytes[bitmap * bs + bit / 8] &= !(1 << (bit % 8));
        }
        let gd = (first + 1) * bs;
        let free = u32::from_le_bytes(target.bytes[1036..1040].try_into().unwrap()) + 12;
        w32(&mut target.bytes, 1036, free);
        w16(&mut target.bytes, gd + 12, free as u16);
        let editor = ExtEditor::open(
            target,
            journal,
            ExtEditRegion {
                offset: 0,
                length: ((first + 128) * bs) as u64,
            },
            ExtEditBinding {
                volume: [3; 32],
                generation: 7,
            },
            limits(),
            &r,
        )
        .unwrap();
        let file = editor
            .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
            .unwrap();
        let batch = editor.plan_extend(&file, &input(1), &r).unwrap();
        let roles = &batch.ordered.as_ref().unwrap().data;
        assert_eq!(roles.len(), 1);
        assert_eq!(
            (roles[0].logical_block, roles[0].origin, roles[0].bytes),
            (0, OrderedOrigin::AuditedFree, bs)
        );
        drop((batch, file, editor));
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn projection_lookup_exhaustion_after_native_read_preserves_evidence_budget_and_storage() {
    let r = resources();
    let mut editor = open(1024, &r);
    let file = editor
        .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
        .unwrap();
    let baseline = r.memory.used();
    let original = editor.target.storage.bytes.clone();
    let probe = ProjectionProbe {
        armed: Arc::new(AtomicBool::new(false)),
        seen: Arc::new(AtomicBool::new(false)),
        cancel: None,
    };
    editor.target.storage.probe = Some(probe.clone());
    let mut input = input(3);
    input.arm = Some(probe.armed.clone());
    let mut observed = false;
    // Find a bounded ceiling inside projection without duplicating its cost model.
    for work in (128..8192).step_by(32) {
        editor.limits.work = work;
        probe.armed.store(false, Ordering::SeqCst);
        probe.seen.store(false, Ordering::SeqCst);
        match editor.plan_extend(&file, &input, &r) {
            Ok(batch) => drop(batch),
            Err(error) => {
                assert_eq!(error.kind, ErrorKind::BudgetExhausted);
                if probe.seen.load(Ordering::SeqCst) {
                    observed = true;
                }
            }
        }
        assert_eq!(r.memory.used(), baseline);
        assert_eq!(editor.target.storage.bytes, original);
        if observed {
            break;
        }
    }
    assert!(
        observed,
        "no budget ceiling reached the projected-read phase"
    );
    drop(file);
    let (target, journal, _) = editor.into_stores();
    assert_eq!((target.writes, journal.writes), (0, 0));
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn sealed_native_partition_preserves_exact_tail_ranges_and_refunds_its_lease() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let editor = open(bs, &r);
        let file = editor
            .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
            .unwrap();
        let baseline = r.memory.used();
        let batch = editor.plan_extend(&file, &input(bs + 64), &r).unwrap();
        let original_count = batch.patches().len();
        let source = batch.source;
        let generation = batch.generation;
        let partition = batch
            .into_ordered_patches(source, generation, 20000, &r)
            .unwrap();
        assert_eq!(partition.binding(), (source, generation));
        assert_eq!(partition.data().len(), 3);
        assert_eq!(partition.data()[0].expected().len(), 17);
        assert_eq!(
            partition.data()[0].offset(),
            fixture(bs).1 as u64 + (bs - 17) as u64
        );
        assert_eq!(
            partition.metadata().len() + partition.data().len(),
            original_count
        );
        for data in partition.data() {
            for metadata in partition.metadata() {
                let data_block = data.offset() / bs as u64;
                let metadata_end = metadata.offset() + metadata.expected().len() as u64 - 1;
                assert!(
                    data_block < metadata.offset() / bs as u64
                        || data_block > metadata_end / bs as u64
                );
            }
        }
        drop(partition);
        assert_eq!(r.memory.used(), baseline);
        assert_eq!(editor.target.storage.writes, 0);
    }
}

#[test]
fn sealed_native_partition_refuses_binding_missing_duplicate_and_work_failures_without_writes() {
    for case in 0..6 {
        let r = resources();
        let editor = open(1024, &r);
        let file = editor
            .open_file(&[NativeName::Bytes(b"alias".to_vec())], &r)
            .unwrap();
        let baseline = r.memory.used();
        let mut batch = editor.plan_extend(&file, &input(1088), &r).unwrap();
        let mut source = batch.source;
        let generation = batch.generation;
        let mut work = 20000;
        match case {
            0 => source ^= 1,
            1 => batch.ordered = None,
            2 => batch.ordered.as_mut().unwrap().data[0].offset += 1,
            3 => {
                let evidence = batch.ordered.as_mut().unwrap();
                evidence.data[1] = evidence.data[0];
            }
            4 => work = 1,
            5 => r.cancellation.cancel(),
            _ => unreachable!(),
        }
        let error = batch
            .into_ordered_patches(source, generation, work, &r)
            .err()
            .unwrap();
        assert_eq!(
            error.kind,
            match case {
                0 => ErrorKind::StalePlan,
                1 => ErrorKind::Unsupported,
                2 | 3 => ErrorKind::InvalidOperation,
                4 => ErrorKind::BudgetExhausted,
                5 => ErrorKind::Cancelled,
                _ => unreachable!(),
            }
        );
        assert_eq!(r.memory.used(), baseline);
        assert_eq!(editor.target.storage.writes, 0);
    }
}
