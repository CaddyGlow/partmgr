#![cfg(feature = "std")]

use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, NativeName, Resources},
    fs_fat_audit::FatAuditLimits,
    fs_fat_edit::{
        FatEditBinding, FatEditLimits, FatEditRegion, FatEditState, FatEditor, FatReplacement,
    },
    fs_undo::{self, UndoBinding, UndoLimits, UndoState},
    storage::Storage,
};
use std::{
    io,
    sync::{Arc, Mutex},
};
const BASE: usize = 4096;
const LENGTH: usize = 65536;
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
fn w(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn d(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn fat(b: &mut [u8], n: usize, value: u16) {
    let at = 512 + n * 3 / 2;
    let old = u16::from_le_bytes(b[at..at + 2].try_into().unwrap());
    w(
        b,
        at,
        if n & 1 == 0 {
            (old & 0xf000) | value
        } else {
            (old & 0x000f) | (value << 4)
        },
    );
}
// Independent packed FAT12 specification fixture with deliberately fragmented allocation.
fn fixture() -> Vec<u8> {
    let mut b = vec![0; LENGTH];
    b[..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
    w(&mut b, 11, 512);
    b[13] = 1;
    w(&mut b, 14, 1);
    b[16] = 1;
    w(&mut b, 17, 16);
    w(&mut b, 19, 128);
    b[21] = 0xf8;
    w(&mut b, 22, 1);
    w(&mut b, 510, 0xaa55);
    for (n, v) in [
        (0, 0xff8),
        (1, 0xfff),
        (2, 4),
        (4, 3),
        (3, 0xfff),
        (5, 0xfff),
    ] {
        fat(&mut b, n, v);
    }
    for (slot, name, first, length) in [(0, b"PAYLOAD BIN", 2, 1300), (1, b"KEEP    BIN", 5, 7)] {
        let at = 1024 + slot * 32;
        b[at..at + 11].copy_from_slice(name);
        b[at + 11] = 0x20;
        w(&mut b, at + 26, first);
        d(&mut b, at + 28, length);
    }
    let payload: Vec<_> = (0..1300).map(|i| ((i * 17 + 3) % 251) as u8).collect();
    for (i, cluster) in [2, 4, 3].iter().enumerate() {
        let n = (1300 - i * 512).min(512);
        let at = 1536 + (cluster - 2) * 512;
        b[at..at + 512].fill(0xa7);
        b[at..at + n].copy_from_slice(&payload[i * 512..i * 512 + n]);
    }
    b[3072..3079].copy_from_slice(b"keep!!!");
    let mut container = vec![0xa5; BASE];
    container.extend(b);
    container.extend([0x5a; 2048]);
    container
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> FatEditLimits {
    FatEditLimits {
        audit: FatAuditLimits {
            clusters: 256,
            entries: 16,
            directory_slots: 64,
            findings: 16,
        },
        file_clusters: 512,
        affected_bytes: 8192,
        replacements: 8,
        work: 1024,
        undo: UndoLimits {
            patches: 128,
            body_bytes: 65536,
        },
    }
}
fn binding() -> FatEditBinding {
    FatEditBinding {
        volume: [7; 32],
        generation: 19,
    }
}
fn undo_binding() -> UndoBinding {
    UndoBinding {
        volume: [7; 32],
        generation: 19,
        transaction: [8; 16],
    }
}
fn region() -> FatEditRegion {
    FatEditRegion {
        offset: BASE as u64,
        length: LENGTH as u64,
    }
}
fn name(alias: &[u8; 11]) -> [NativeName; 1] {
    [NativeName::Bytes(alias.to_vec())]
}
fn editor(clock: Arc<Mutex<Clock>>, r: &Resources) -> FatEditor<Model, Model> {
    FatEditor::open(
        Model::new(fixture(), clock.clone()),
        Model::new(vec![0; 65536], clock),
        region(),
        binding(),
        limits(),
        r,
    )
    .unwrap()
}
#[test]
fn resize_fragmented_growth_truncate_zero_and_reallocate() {
    let r = resources();
    let mut e = editor(Arc::new(Mutex::new(Clock::default())), &r);
    let mut expected: Vec<u8> = (0..1300).map(|i| ((i * 17 + 3) % 251) as u8).collect();
    for (tx, append, length) in [
        (1, Some(vec![0x42; 700]), 2000),
        (2, None, 513),
        (3, None, 0),
        (4, Some(vec![0x73; 900]), 900),
    ] {
        let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
        let batch = if let Some(bytes) = &append {
            expected.extend(bytes);
            e.plan_extend_bytes(&f, bytes, &r).unwrap()
        } else {
            expected.truncate(length);
            e.plan_truncate(&f, length as u64, &r).unwrap()
        };
        assert_eq!(batch.resize_report().unwrap().new_length, length as u64);
        e.commit(batch, [tx; 16], &r).unwrap();
        assert_eq!(
            e.read_at(&f, 0, &mut [0], &r).unwrap_err().kind,
            ErrorKind::StalePlan
        );
        let new = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
        assert_eq!(new.len(), length as u64);
        let mut actual = vec![0; length];
        assert_eq!(e.read_at(&new, 0, &mut actual, &r).unwrap(), length);
        assert_eq!(actual, expected);
        assert_eq!(&new.raw_metadata()[..20], &f.raw_metadata()[..20]);
        if length == 0 {
            assert_eq!(&new.raw_metadata()[26..28], &[0, 0]);
        }
        let keep = e.open_file(&name(b"KEEP    BIN"), &r).unwrap();
        let mut unrelated = [0; 7];
        e.read_at(&keep, 0, &mut unrelated, &r).unwrap();
        assert_eq!(&unrelated, b"keep!!!");
    }
    drop(e);
    assert_eq!(r.memory.used(), 0);
}
fn resize_batch(
    e: &FatEditor<Model, Model>,
    f: &partmgr::fs_fat_edit::FatEditFile,
    operation: u8,
    r: &Resources,
) -> partmgr::fs_fat_edit::FatEditBatch {
    match operation {
        0 => e.plan_extend_bytes(f, &[0x42; 700], r).unwrap(),
        1 => e.plan_truncate(f, 513, r).unwrap(),
        _ => e.plan_truncate(f, 0, r).unwrap(),
    }
}
#[test]
fn resize_every_write_barrier_cut_owned_recovery_and_restart_models() {
    let r = resources();
    for operation in 0..3 {
        let c = Arc::new(Mutex::new(Clock::default()));
        let mut done = editor(c.clone(), &r);
        let f = done.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
        let b = resize_batch(&done, &f, operation, &r);
        let mut after = fixture();
        for p in b.patches() {
            let at = BASE + p.offset() as usize;
            after[at..at + p.replacement().len()].copy_from_slice(p.replacement());
        }
        done.commit(b, [8; 16], &r).unwrap();
        let events = c.lock().unwrap().events;
        drop((done, f));
        for restart in [None, Some(false), Some(true)] {
            for cut in 1..=events {
                let c = Arc::new(Mutex::new(Clock {
                    events: 0,
                    fail: Some(cut),
                }));
                let mut e = editor(c.clone(), &r);
                let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
                let b = resize_batch(&e, &f, operation, &r);
                e.commit(b, [8; 16], &r).unwrap_err();
                assert_eq!(e.state(), FatEditState::NeedsRecovery);
                assert!(e.plan_truncate(&f, 0, &r).is_err());
                c.lock().unwrap().fail = None;
                let (target, state, status) = if let Some(retain) = restart {
                    let (mut target, mut journal, _) = e.into_stores();
                    target.crash(retain);
                    journal.crash(retain);
                    let Ok(status) = fs_undo::inspect(&journal, &r) else {
                        assert_eq!(target.bytes, fixture());
                        assert!(
                            FatEditor::recover_open(
                                target,
                                journal,
                                region(),
                                undo_binding(),
                                limits(),
                                &r
                            )
                            .is_err()
                        );
                        drop(f);
                        assert_eq!(r.memory.used(), 0);
                        continue;
                    };
                    let e = FatEditor::recover_open(
                        target,
                        journal,
                        region(),
                        undo_binding(),
                        limits(),
                        &r,
                    )
                    .unwrap();
                    let (target, _, state) = e.into_stores();
                    (target, state, status)
                } else {
                    let status = e.recover(&r).unwrap();
                    let (target, _, state) = e.into_stores();
                    (target, state, status)
                };
                assert_eq!(state, FatEditState::Ready);
                assert_eq!(
                    target.bytes,
                    if status.state == UndoState::Committed {
                        after.clone()
                    } else {
                        fixture()
                    },
                    "operation={operation} cut={cut} restart={restart:?}"
                );
                drop(f);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}
// Independently assembled FAT32 boot/FAT/directory/FSInfo fields; no production builder.
fn active_fat32_fixture() -> (Vec<u8>, FatEditRegion) {
    let clusters = 65525usize;
    let sectors = 32 + 2 * 512 + clusters;
    let mut b = vec![0; sectors * 512];
    b[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    w(&mut b, 11, 512);
    b[13] = 1;
    w(&mut b, 14, 32);
    b[16] = 2;
    b[21] = 0xf8;
    d(&mut b, 32, sectors as u32);
    d(&mut b, 36, 512);
    w(&mut b, 40, 0x81);
    d(&mut b, 44, 2);
    w(&mut b, 48, 1);
    w(&mut b, 50, 6);
    w(&mut b, 510, 0xaa55);
    let boot = b[..512].to_vec();
    b[6 * 512..7 * 512].copy_from_slice(&boot);
    for info in [512, 7 * 512] {
        d(&mut b, info, 0x41615252);
        d(&mut b, info + 484, 0x61417272);
        d(&mut b, info + 488, (clusters - 1) as u32); // deliberately stale, explicit reconciliation report
        d(&mut b, info + 492, 4);
        d(&mut b, info + 508, 0xaa550000);
    }
    let fat = 32 * 512 + 512 * 512;
    for (cluster, value) in [
        (0, 0xaffffff8),
        (1, 0xbfffffff),
        (2, 0xcfffffff),
        (3, 0xdfffffff),
        (4, 0xe0000000),
    ] {
        d(&mut b, fat + cluster * 4, value);
    }
    // Inactive FAT is deliberately unrelated and must remain byte-exact.
    b[32 * 512..32 * 512 + 512 * 512].fill(0x69);
    let data = (32 + 2 * 512) * 512;
    b[data..data + 11].copy_from_slice(b"PAYLOAD BIN");
    b[data + 11] = 0x20;
    w(&mut b, data + 26, 3);
    d(&mut b, data + 28, 7);
    b[data + 512..data + 519].copy_from_slice(b"initial");
    let region = FatEditRegion {
        offset: BASE as u64,
        length: b.len() as u64,
    };
    let mut container = vec![0xa5; BASE];
    container.extend(b);
    container.extend([0x5a; 2048]);
    (container, region)
}
#[test]
fn resize_active_fat32_reserved_bits_fsinfo_backup_and_invalid_gate() {
    let r = resources();
    let (before, selected) = active_fat32_fixture();
    let mut l = limits();
    l.audit.clusters = 65525;
    for bad in [false, true] {
        let mut source = before.clone();
        if bad {
            source[BASE + 7 * 512] ^= 1;
        }
        let c = Arc::new(Mutex::new(Clock::default()));
        let mut e = FatEditor::open(
            Model::new(source, c.clone()),
            Model::new(vec![0; 65536], c.clone()),
            selected,
            binding(),
            l,
            &r,
        )
        .unwrap();
        let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
        let planned = e.plan_extend_bytes(&f, &[0x42; 700], &r);
        if bad {
            assert_eq!(planned.err().unwrap().kind, ErrorKind::Unsupported);
            assert_eq!(c.lock().unwrap().events, 0);
        } else {
            let b = planned.unwrap();
            assert!(b.resize_report().unwrap().reconciled_fsinfo);
            let mut expected = before.clone();
            for patch in b.patches() {
                let at = BASE + patch.offset() as usize;
                expected[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
            }
            e.commit(b, [8; 16], &r).unwrap();
            let (target, _, _) = e.into_stores();
            assert_eq!(target.bytes, expected);
            let fat = BASE + 32 * 512 + 512 * 512;
            assert_eq!(
                u32::from_le_bytes(target.bytes[fat + 12..fat + 16].try_into().unwrap()),
                0xd0000004
            );
            assert_eq!(
                u32::from_le_bytes(target.bytes[fat + 16..fat + 20].try_into().unwrap()),
                0xefffffff
            );
            for info in [BASE + 512, BASE + 7 * 512] {
                assert_eq!(
                    u32::from_le_bytes(target.bytes[info + 488..info + 492].try_into().unwrap()),
                    65522
                );
                assert_eq!(
                    u32::from_le_bytes(target.bytes[info + 492..info + 496].try_into().unwrap()),
                    5
                );
            }
        }
        drop(f);
    }
    assert_eq!(r.memory.used(), 0);
}
struct Append {
    id: partmgr::fs_core::ObjectId,
    changed: std::sync::atomic::AtomicBool,
    stale: bool,
}
impl partmgr::fs_core::FileRead for Append {
    fn identity(&self) -> &partmgr::fs_core::ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        if self.changed.load(std::sync::atomic::Ordering::Relaxed) && self.stale {
            701
        } else {
            700
        }
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> partmgr::fs_core::Result<usize> {
        r.cancellation.check()?;
        let n = out.len().min(13).min(700usize.saturating_sub(at as usize));
        out[..n].fill(0x42);
        self.changed
            .store(true, std::sync::atomic::Ordering::Relaxed);
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
#[test]
fn resize_deferred_short_reads_revalidation_limits_and_readonly() {
    let r = resources();
    let c = Arc::new(Mutex::new(Clock::default()));
    let mut e = editor(c.clone(), &r);
    let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
    for stale in [true, false] {
        let input = Append {
            id: partmgr::fs_core::ObjectId {
                source: 999,
                generation: 0,
                native: vec![1],
            },
            changed: false.into(),
            stale,
        };
        let b = e.plan_extend(&f, &input, &r);
        if stale {
            assert_eq!(b.err().unwrap().kind, ErrorKind::StalePlan);
            assert_eq!(c.lock().unwrap().events, 0);
        } else {
            e.commit(b.unwrap(), [8; 16], &r).unwrap();
        }
    }
    drop((f, e));
    assert_eq!(r.memory.used(), 0);
    for (bytes, work) in [(100, 1024), (8192, 1)] {
        let mut l = limits();
        l.affected_bytes = bytes;
        l.work = work;
        let c = Arc::new(Mutex::new(Clock::default()));
        let e = FatEditor::open(
            Model::new(fixture(), c.clone()),
            Model::new(vec![0; 65536], c.clone()),
            region(),
            binding(),
            l,
            &r,
        )
        .unwrap();
        let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
        assert_eq!(
            e.plan_extend_bytes(&f, &[0; 700], &r).err().unwrap().kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(c.lock().unwrap().events, 0);
    }
    let mut source = fixture();
    source[BASE + 1024 + 11] |= 1;
    let c = Arc::new(Mutex::new(Clock::default()));
    let e = FatEditor::open(
        Model::new(source, c.clone()),
        Model::new(vec![0; 65536], c.clone()),
        region(),
        binding(),
        limits(),
        &r,
    )
    .unwrap();
    assert!(e.open_file(&name(b"PAYLOAD BIN"), &r).is_err());
    assert_eq!(c.lock().unwrap().events, 0);
    drop(e);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn resize_out_of_space_cancel_and_stale_overlapping_plans() {
    let r = resources();
    let c = Arc::new(Mutex::new(Clock::default()));
    let mut e = editor(c.clone(), &r);
    let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
    assert_eq!(
        e.plan_extend_bytes(&f, &vec![0; 65536], &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidOperation
    );
    assert_eq!(c.lock().unwrap().events, 0);
    let a = e.plan_extend_bytes(&f, &[0x42; 700], &r).unwrap();
    let b = e.plan_truncate(&f, 0, &r).unwrap();
    e.commit(a, [8; 16], &r).unwrap();
    assert_eq!(
        e.commit(b, [9; 16], &r).unwrap_err().source.kind,
        ErrorKind::StalePlan
    );
    drop(f);
    let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
    r.cancellation.cancel();
    assert_eq!(
        e.plan_truncate(&f, 0, &r).err().unwrap().kind,
        ErrorKind::Cancelled
    );
    drop((f, e));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn reusable_file_batch_commit_generation_and_unrelated_bytes() {
    let r = resources();
    let clock = Arc::new(Mutex::new(Clock::default()));
    let mut editor = editor(clock, &r);
    let file = editor.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
    let keep = editor.open_file(&name(b"KEEP    BIN"), &r).unwrap();
    let mut buffer = [0; 73];
    editor.read_at(&file, 511, &mut buffer, &r).unwrap();
    assert_eq!(
        buffer,
        std::array::from_fn(|i| (((511 + i) * 17 + 3) % 251) as u8)
    );
    let batch = editor
        .plan_batch(
            &[
                FatReplacement {
                    file: &file,
                    offset: 500,
                    bytes: &[42; 600],
                },
                FatReplacement {
                    file: &keep,
                    offset: 1,
                    bytes: b"XYZ",
                },
            ],
            &r,
        )
        .unwrap();
    assert_eq!(batch.affected_bytes(), 603);
    assert_eq!(batch.patches().len(), 4);
    let mut expected = fixture();
    for patch in batch.patches() {
        let at = BASE + patch.offset() as usize;
        assert_eq!(&expected[at..at + patch.expected().len()], patch.expected());
        expected[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
    }
    let stale = editor
        .plan_batch(
            &[FatReplacement {
                file: &keep,
                offset: 4,
                bytes: b"A",
            }],
            &r,
        )
        .unwrap();
    assert_eq!(
        editor.commit(batch, [8; 16], &r).unwrap().state,
        UndoState::Committed
    );
    assert_eq!(editor.generation(), 1);
    assert_eq!(
        editor.read_at(&file, 0, &mut buffer, &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert_eq!(
        editor.commit(stale, [9; 16], &r).unwrap_err().source.kind,
        ErrorKind::StalePlan
    );
    let current = editor.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
    editor.read_at(&current, 500, &mut buffer, &r).unwrap();
    assert_eq!(buffer, [42; 73]);
    let (target, journal, state) = editor.into_stores();
    assert_eq!(state, FatEditState::Ready);
    assert_eq!(target.bytes, expected);
    assert_eq!(target.durable, expected);
    assert_eq!(
        fs_undo::inspect(&journal, &r).unwrap().state,
        UndoState::Committed
    );
    drop((file, keep, current, target, journal));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn audit_caps_overlap_foreign_handles_cancel_and_refunds() {
    let r = resources();
    let c = Arc::new(Mutex::new(Clock::default()));
    let mut bad = fixture();
    fat(&mut bad[BASE..], 6, 0xfff);
    assert_eq!(
        FatEditor::open(
            Model::new(bad, c.clone()),
            Model::new(vec![0; 65536], c.clone()),
            region(),
            binding(),
            limits(),
            &r
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::InvalidData
    );
    assert_eq!(r.memory.used(), 0);
    let editor = editor(c.clone(), &r);
    let file = editor.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
    assert_eq!(
        editor
            .plan_batch(
                &[FatReplacement {
                    file: &file,
                    offset: 1299,
                    bytes: b"XY"
                }],
                &r
            )
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidOperation
    );
    assert_eq!(
        editor
            .plan_batch(
                &[
                    FatReplacement {
                        file: &file,
                        offset: 2,
                        bytes: b"XY"
                    },
                    FatReplacement {
                        file: &file,
                        offset: 3,
                        bytes: b"Q"
                    }
                ],
                &r
            )
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidOperation
    );
    let other = crate::editor(c, &r);
    assert_eq!(
        other.read_at(&file, 0, &mut [0], &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    r.cancellation.cancel();
    assert_eq!(
        editor.read_at(&file, 0, &mut [0], &r).unwrap_err().kind,
        ErrorKind::Cancelled
    );
    drop((editor, other, file));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn every_write_and_barrier_cut_blocks_and_recovers_in_same_owned_session() {
    let r = resources();
    let clock = Arc::new(Mutex::new(Clock::default()));
    let mut complete = editor(clock.clone(), &r);
    let file = complete.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
    let batch = complete
        .plan_batch(
            &[FatReplacement {
                file: &file,
                offset: 500,
                bytes: &[42; 600],
            }],
            &r,
        )
        .unwrap();
    let mut after = fixture();
    for patch in batch.patches() {
        let at = BASE + patch.offset() as usize;
        after[at..at + patch.replacement().len()].copy_from_slice(patch.replacement());
    }
    complete.commit(batch, [8; 16], &r).unwrap();
    let events = clock.lock().unwrap().events;
    assert!(events >= 16);
    drop((complete, file));
    for cut in 1..=events {
        let clock = Arc::new(Mutex::new(Clock {
            events: 0,
            fail: Some(cut),
        }));
        let mut editor = editor(clock.clone(), &r);
        let file = editor.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
        let batch = editor
            .plan_batch(
                &[FatReplacement {
                    file: &file,
                    offset: 500,
                    bytes: &[42; 600],
                }],
                &r,
            )
            .unwrap();
        let error = editor.commit(batch, [8; 16], &r).unwrap_err();
        assert!(std::error::Error::source(&error).is_some());
        assert_eq!(editor.state(), FatEditState::NeedsRecovery);
        assert_eq!(
            editor.read_at(&file, 0, &mut [0], &r).unwrap_err().kind,
            ErrorKind::InvalidOperation
        );
        clock.lock().unwrap().fail = None;
        let status = editor.recover(&r).unwrap();
        assert_eq!(editor.state(), FatEditState::Ready);
        assert_eq!(
            editor.read_at(&file, 0, &mut [0], &r).unwrap_err().kind,
            ErrorKind::StalePlan
        );
        let (target, _, _) = editor.into_stores();
        assert_eq!(
            target.bytes,
            if status.state == UndoState::Committed {
                after.clone()
            } else {
                fixture()
            },
            "cut {cut}"
        );
        drop((file, target));
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn restart_at_every_cut_with_both_unflushed_persistence_models() {
    let r = resources();
    let c = Arc::new(Mutex::new(Clock::default()));
    let mut done = editor(c.clone(), &r);
    let f = done.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
    let b = done
        .plan_batch(
            &[FatReplacement {
                file: &f,
                offset: 500,
                bytes: &[42; 600],
            }],
            &r,
        )
        .unwrap();
    let mut after = fixture();
    for p in b.patches() {
        let at = BASE + p.offset() as usize;
        after[at..at + p.replacement().len()].copy_from_slice(p.replacement());
    }
    done.commit(b, [8; 16], &r).unwrap();
    let events = c.lock().unwrap().events;
    drop((done, f));
    for retain in [false, true] {
        for cut in 1..=events {
            let c = Arc::new(Mutex::new(Clock {
                events: 0,
                fail: Some(cut),
            }));
            let mut e = editor(c.clone(), &r);
            let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
            let b = e
                .plan_batch(
                    &[FatReplacement {
                        file: &f,
                        offset: 500,
                        bytes: &[42; 600],
                    }],
                    &r,
                )
                .unwrap();
            e.commit(b, [8; 16], &r).unwrap_err();
            let (mut target, mut journal, state) = e.into_stores();
            assert_eq!(state, FatEditState::NeedsRecovery);
            drop(f);
            target.crash(retain);
            journal.crash(retain);
            c.lock().unwrap().fail = None;
            match fs_undo::inspect(&journal, &r) {
                Ok(status) => {
                    let expected = if status.state == UndoState::Committed {
                        after.clone()
                    } else {
                        fixture()
                    };
                    let e = FatEditor::recover_open(
                        target,
                        journal,
                        region(),
                        undo_binding(),
                        limits(),
                        &r,
                    )
                    .unwrap();
                    let (target, _, state) = e.into_stores();
                    assert_eq!(state, FatEditState::Ready);
                    assert_eq!(target.bytes, expected, "cut{cut} retain{retain}");
                }
                Err(_) => {
                    assert_eq!(
                        target.bytes,
                        fixture(),
                        "invalid unpublished header must precede any target write: cut{cut} retain{retain}"
                    );
                    assert!(
                        FatEditor::recover_open(
                            target,
                            journal,
                            region(),
                            undo_binding(),
                            limits(),
                            &r
                        )
                        .is_err()
                    );
                }
            }
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn planning_byte_work_patch_caps_and_preflight_failure_leave_storage_untouched() {
    let r = resources();
    for case in 0..3 {
        let c = Arc::new(Mutex::new(Clock::default()));
        let mut l = limits();
        match case {
            0 => l.affected_bytes = 1,
            1 => l.work = 1,
            _ => l.undo.patches = 1,
        }
        let e = FatEditor::open(
            Model::new(fixture(), c.clone()),
            Model::new(vec![0; 65536], c.clone()),
            region(),
            binding(),
            l,
            &r,
        )
        .unwrap();
        let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
        assert_eq!(
            e.plan_batch(
                &[FatReplacement {
                    file: &f,
                    offset: 500,
                    bytes: &[42; 600]
                }],
                &r
            )
            .err()
            .unwrap()
            .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(c.lock().unwrap().events, 0);
        drop((f, e));
        assert_eq!(r.memory.used(), 0);
    }
    let c = Arc::new(Mutex::new(Clock::default()));
    let mut l = limits();
    l.undo.body_bytes = 1;
    let mut e = FatEditor::open(
        Model::new(fixture(), c.clone()),
        Model::new(vec![0; 65536], c.clone()),
        region(),
        binding(),
        l,
        &r,
    )
    .unwrap();
    let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
    let b = e
        .plan_batch(
            &[FatReplacement {
                file: &f,
                offset: 500,
                bytes: b"x",
            }],
            &r,
        )
        .unwrap();
    assert_eq!(
        e.commit(b, [8; 16], &r).unwrap_err().source.kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(e.state(), FatEditState::Ready);
    assert_eq!(e.generation(), 0);
    assert_eq!(c.lock().unwrap().events, 0);
    drop((f, e));
    assert_eq!(r.memory.used(), 0);
}

struct NativeFault {
    storage: partmgr::storage::FileStorage,
    clock: Arc<Mutex<Clock>>,
}
impl Storage for NativeFault {
    fn len(&self) -> io::Result<u64> {
        self.storage.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.storage.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        let fail = {
            let mut c = self.clock.lock().unwrap();
            c.events += 1;
            c.fail == Some(c.events)
        };
        if fail {
            let n = bytes.len().div_ceil(2);
            self.storage.write_at(at, &bytes[..n])?;
            Err(io::Error::other("native injected partial write"))
        } else {
            self.storage.write_at(at, bytes)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let fail = {
            let mut c = self.clock.lock().unwrap();
            c.events += 1;
            c.fail == Some(c.events)
        };
        if fail {
            Err(io::Error::other("native injected flush failure"))
        } else {
            self.storage.flush()
        }
    }
}
#[test]
#[ignore = "explicit native FAT editing gate; requires PARTMGR_FAT_EDIT_EVIDENCE, mkfs.fat, mcopy and fsck.fat"]
fn native_fat12_16_32_every_io_cut_payload_metadata_and_bounded_region() {
    native_gate(
        "range",
        std::path::PathBuf::from(
            std::env::var_os("PARTMGR_FAT_EDIT_EVIDENCE")
                .expect("native gate requires evidence destination"),
        ),
        &native_provenance(),
    );
}
#[test]
#[ignore = "explicit native FAT resize gate; requires PARTMGR_FAT_EDIT_EVIDENCE, mkfs.fat, mcopy and fsck.fat"]
fn native_fat12_16_32_resize_every_io_cut() {
    let out = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_FAT_EDIT_EVIDENCE")
            .expect("native gate requires evidence destination"),
    );
    assert!(out.is_absolute());
    std::fs::create_dir(&out).expect("fresh evidence destination required");
    let provenance = native_provenance();
    for operation in ["extend", "truncate", "zero", "empty_extend"] {
        native_gate(operation, out.join(operation), &provenance);
    }
}
fn native_provenance() -> String {
    use sha2::{Digest, Sha256};
    let mut provenance = String::from("source_hash_capture=top-level-gate-start\n");
    for path in [
        "src/fs_fat_edit.rs",
        "src/fs_fat_edit_resize.rs",
        "src/fs_fat.rs",
        "src/fs_fat_audit.rs",
        "src/fs_undo.rs",
        "src/fs_core.rs",
        "src/fs_file.rs",
        "src/storage.rs",
        "tests/fs_fat_edit.rs",
        "Cargo.lock",
    ] {
        provenance.push_str(&format!(
            "source={path} sha256={:x}\n",
            Sha256::digest(std::fs::read(path).unwrap())
        ));
    }
    provenance.push_str(&format!(
        "test_binary_sha256={:x}\n",
        Sha256::digest(std::fs::read(std::env::current_exe().unwrap()).unwrap())
    ));
    provenance
}
fn native_gate(operation: &str, out: std::path::PathBuf, provenance: &str) {
    use sha2::{Digest, Sha256};
    use std::{fs, process::Command};
    assert!(out.is_absolute());
    fs::create_dir(&out).expect("fresh evidence destination required");
    let mut receipt = String::from(
        "profile=exclusive FAT existing-file operations; native IO cuts, not physical power-loss qualification\n",
    );
    receipt.push_str(&format!("operation={operation}\n"));
    for tool in ["mkfs.fat", "mcopy", "fsck.fat"] {
        let path = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
            .expect("enabled native gate requires tool");
        receipt.push_str(&format!(
            "tool={tool} path={} sha256={:x}\n",
            path.display(),
            Sha256::digest(fs::read(&path).unwrap())
        ));
    }
    let run = |receipt: &mut String, tool: &str, args: Vec<String>| {
        let result = Command::new(tool).args(&args).output().unwrap();
        let n = receipt.matches("command=").count();
        let stdout = format!("command-{n:03}-{tool}.stdout");
        let stderr = format!("command-{n:03}-{tool}.stderr");
        fs::write(out.join(&stdout), &result.stdout).unwrap();
        fs::write(out.join(&stderr), &result.stderr).unwrap();
        receipt.push_str(&format!("command={tool} {args:?}\nstatus={}\nstdout={stdout} sha256={:x}\nstderr={stderr} sha256={:x}\n",result.status,Sha256::digest(&result.stdout),Sha256::digest(&result.stderr)));
        fs::write(out.join("receipt.txt"), &*receipt).unwrap();
        assert!(
            result.status.success(),
            "{tool}: {} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    };
    run(&mut receipt, "mkfs.fat", vec!["--help".into()]);
    run(&mut receipt, "mcopy", vec!["-V".into()]);
    run(&mut receipt, "fsck.fat", vec!["--help".into()]);
    let payload: Vec<_> = (0..131089)
        .map(|i| ((i * 37 + i / 19 + 11) % 251) as u8)
        .collect();
    let host = out.join("payload.bin");
    fs::write(&host, &payload).unwrap();
    let keep = out.join("keep.bin");
    fs::write(&keep, b"unrelated native file").unwrap();
    let mut native_limits = limits();
    native_limits.audit.clusters = 131072;
    native_limits.audit.entries = 64;
    native_limits.audit.directory_slots = 256;
    native_limits.file_clusters = 1024;
    native_limits.work = 65536;
    let replacement = [0x69; 4099];
    let mut new_payload = payload.clone();
    new_payload[511..511 + replacement.len()].copy_from_slice(&replacement);
    new_payload[100001..100008].copy_from_slice(b"updated");
    let payload = if operation == "empty_extend" {
        Vec::new()
    } else {
        payload
    };
    if operation == "empty_extend" {
        fs::write(&host, &payload).unwrap();
    }
    if operation == "extend" || operation == "empty_extend" {
        new_payload = payload.clone();
        new_payload.extend([0x69; 4099]);
    }
    if operation == "truncate" {
        new_payload = payload[..100001].to_vec();
    }
    if operation == "zero" {
        new_payload.clear();
    }
    for (family, length) in [(12, 1474560usize), (16, 8 << 20), (32, 40 << 20)] {
        let seed = out.join(format!("fat{family}-seed.img"));
        fs::File::create(&seed)
            .unwrap()
            .set_len(length as u64)
            .unwrap();
        run(
            &mut receipt,
            "mkfs.fat",
            vec![
                "-F".into(),
                family.to_string(),
                "-S".into(),
                "512".into(),
                "-s".into(),
                "1".into(),
                seed.display().to_string(),
            ],
        );
        run(
            &mut receipt,
            "mcopy",
            vec![
                "-i".into(),
                seed.display().to_string(),
                host.display().to_string(),
                "::PAYLOAD.BIN".into(),
            ],
        );
        run(
            &mut receipt,
            "mcopy",
            vec![
                "-i".into(),
                seed.display().to_string(),
                keep.display().to_string(),
                "::KEEP.BIN".into(),
            ],
        );
        run(
            &mut receipt,
            "fsck.fat",
            vec!["-n".into(), seed.display().to_string()],
        );
        let mut before = vec![0xa5; BASE];
        before.extend(fs::read(&seed).unwrap());
        before.extend([0x5a; 2048]);
        let selected = FatEditRegion {
            offset: BASE as u64,
            length: length as u64,
        };
        let container = out.join(format!("fat{family}-container.img"));
        let journal = out.join(format!("fat{family}-journal.bin"));
        let oracle = out.join(format!("fat{family}-oracle.img"));
        let extracted = out.join(format!("fat{family}-extracted.bin"));
        let mut total = 0usize;
        let mut after = Vec::new();
        let r = resources();
        for cut in 0..128 {
            if cut != 0 && cut > total {
                break;
            }
            fs::write(&container, &before).unwrap();
            fs::write(&journal, vec![0; 65536]).unwrap();
            for path in [&container, &journal] {
                fs::File::open(path).unwrap().sync_all().unwrap();
            }
            let c = Arc::new(Mutex::new(Clock {
                events: 0,
                fail: if cut == 0 { None } else { Some(cut) },
            }));
            let target = NativeFault {
                storage: partmgr::storage::FileStorage::open(&container).unwrap(),
                clock: c.clone(),
            };
            let external = NativeFault {
                storage: partmgr::storage::FileStorage::open(&journal).unwrap(),
                clock: c.clone(),
            };
            let mut e =
                FatEditor::open(target, external, selected, binding(), native_limits, &r).unwrap();
            assert_eq!(
                format!("{:?}", e.geometry().family()),
                format!("Fat{family}")
            );
            let file = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
            let b = match operation {
                "extend" | "empty_extend" => e.plan_extend_bytes(&file, &replacement, &r).unwrap(),
                "truncate" => e.plan_truncate(&file, 100001, &r).unwrap(),
                "zero" => e.plan_truncate(&file, 0, &r).unwrap(),
                _ => e
                    .plan_batch(
                        &[
                            FatReplacement {
                                file: &file,
                                offset: 511,
                                bytes: &replacement,
                            },
                            FatReplacement {
                                file: &file,
                                offset: 100001,
                                bytes: b"updated",
                            },
                        ],
                        &r,
                    )
                    .unwrap(),
            };
            if cut == 0 {
                after = before.clone();
                for p in b.patches() {
                    let at = BASE + p.offset() as usize;
                    after[at..at + p.replacement().len()].copy_from_slice(p.replacement());
                }
                receipt.push_str(&format!("family={family} patches={} affected={} original_sha256={:x} expected_new_sha256={:x}\n",b.patches().len(),b.affected_bytes(),Sha256::digest(&before),Sha256::digest(&after)));
            }
            let result = e.commit(b, [8; 16], &r);
            let status = if cut == 0 {
                let s = result.unwrap();
                total = c.lock().unwrap().events;
                assert!(total < 128);
                s
            } else {
                let error = result.unwrap_err();
                assert_eq!(e.state(), FatEditState::NeedsRecovery);
                receipt.push_str(&format!("family={family} cut={cut} failed_stage={} recovery_required={} target_write_attempted={}\n",error.stage,error.recovery_required,error.target_may_have_changed));
                c.lock().unwrap().fail = None;
                e.recover(&r).unwrap()
            };
            let (target, external, state) = e.into_stores();
            assert_eq!(state, FatEditState::Ready);
            drop((file, target, external));
            assert_eq!(r.memory.used(), 0);
            let actual = fs::read(&container).unwrap();
            let committed = status.state == UndoState::Committed;
            assert_eq!(
                actual,
                if committed {
                    after.clone()
                } else {
                    before.clone()
                },
                "native FAT{family} cut{cut}: only mapped payload may change"
            );
            fs::write(&oracle, &actual[BASE..BASE + length]).unwrap();
            if extracted.exists() {
                fs::remove_file(&extracted).unwrap();
            }
            run(
                &mut receipt,
                "mcopy",
                vec![
                    "-i".into(),
                    format!("{}@@{BASE}", container.display()),
                    "::PAYLOAD.BIN".into(),
                    extracted.display().to_string(),
                ],
            );
            let extracted_bytes = fs::read(&extracted).unwrap();
            assert_eq!(
                extracted_bytes,
                if committed {
                    new_payload.clone()
                } else {
                    payload.clone()
                }
            );
            run(
                &mut receipt,
                "fsck.fat",
                vec!["-n".into(), oracle.display().to_string()],
            );
            assert_eq!(fs::read(&oracle).unwrap(), actual[BASE..BASE + length]);
            assert_eq!(fs::read(&container).unwrap(), actual);
            receipt.push_str(&format!("family={family} cut={cut} result={:?} target_sha256={:x} payload_sha256={:x} journal_sha256={:x} all_other_bytes_unchanged=true\n",status.state,Sha256::digest(&actual),Sha256::digest(&extracted_bytes),Sha256::digest(fs::read(&journal).unwrap())));
            if cut == 0 {
                fs::copy(
                    &container,
                    out.join(format!("fat{family}-committed-container.img")),
                )
                .unwrap();
            }
            fs::write(out.join("receipt.txt"), &receipt).unwrap();
        }
        eprintln!("native FAT{family}: normal plus all {total} write/barrier cuts passed");
    }
    receipt.push_str(provenance);
    receipt.push_str("result=passed\n");
    fs::write(out.join("receipt.txt"), receipt).unwrap();
    for item in fs::read_dir(&out).unwrap() {
        fs::File::open(item.unwrap().path())
            .unwrap()
            .sync_all()
            .unwrap();
    }
    fs::File::open(&out).unwrap().sync_all().unwrap();
    eprintln!("native FAT editing evidence {}", out.display());
}
#[test]
fn pending_journal_open_gate_and_failed_second_publication_reinspection() {
    let r = resources();
    let c = Arc::new(Mutex::new(Clock::default()));
    let mut e = editor(c.clone(), &r);
    let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
    let b = e
        .plan_batch(
            &[FatReplacement {
                file: &f,
                offset: 7,
                bytes: b"first",
            }],
            &r,
        )
        .unwrap();
    e.commit(b, [8; 16], &r).unwrap();
    drop(f);
    let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
    let b = e
        .plan_batch(
            &[FatReplacement {
                file: &f,
                offset: 99,
                bytes: b"second",
            }],
            &r,
        )
        .unwrap();
    {
        let mut c = c.lock().unwrap();
        c.fail = Some(c.events + 1);
    }
    let error = e.commit(b, [9; 16], &r).unwrap_err();
    assert!(!error.target_may_have_changed);
    c.lock().unwrap().fail = None;
    assert_eq!(e.recover(&r).unwrap().state, UndoState::Empty);
    drop(f);
    let f = e.open_file(&name(b"PAYLOAD BIN"), &r).unwrap();
    let mut b = [0; 5];
    e.read_at(&f, 7, &mut b, &r).unwrap();
    assert_eq!(&b, b"first");
    let p = e
        .plan_batch(
            &[FatReplacement {
                file: &f,
                offset: 99,
                bytes: b"third",
            }],
            &r,
        )
        .unwrap();
    e.commit(p, [10; 16], &r).unwrap();
    drop(f);
    let (target, mut journal, _) = e.into_stores();
    journal.bytes[512..1024].fill(0);
    journal.durable.clone_from(&journal.bytes);
    assert_eq!(
        FatEditor::open(target, journal, region(), binding(), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidOperation
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn reserved_fat_media_and_entry_one_encoding_do_not_authorize_editing() {
    let r = resources();
    for (index, value) in [(0, 0xff9), (1, 0xff0)] {
        let c = Arc::new(Mutex::new(Clock::default()));
        let mut bytes = fixture();
        fat(&mut bytes[BASE..], index, value);
        let error = FatEditor::open(
            Model::new(bytes, c.clone()),
            Model::new(vec![0; 65536], c.clone()),
            region(),
            binding(),
            limits(),
            &r,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind, ErrorKind::InvalidData);
        assert_eq!(c.lock().unwrap().events, 0);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn permitted_fat12_reserved_eoc_and_opening_audit_budget_are_explicit() {
    let r = resources();
    let c = Arc::new(Mutex::new(Clock::default()));
    let mut bytes = fixture();
    fat(&mut bytes[BASE..], 1, 0xff8);
    let e = FatEditor::open(
        Model::new(bytes, c.clone()),
        Model::new(vec![0; 65536], c.clone()),
        region(),
        binding(),
        limits(),
        &r,
    )
    .unwrap();
    assert_eq!(e.state(), FatEditState::Ready);
    drop(e);
    assert_eq!(r.memory.used(), 0);
    let mut cap = limits();
    cap.audit.clusters = 1;
    let error = FatEditor::open(
        Model::new(fixture(), c.clone()),
        Model::new(vec![0; 65536], c.clone()),
        region(),
        binding(),
        cap,
        &r,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind, ErrorKind::BudgetExhausted);
    assert!(std::error::Error::source(&error).is_some());
    assert_eq!(c.lock().unwrap().events, 0);
    assert_eq!(r.memory.used(), 0);
}
