#![cfg(feature = "std")]
//! Independent native ext2 geometry cuts on target and external undo storage.
use partmgr::{
    fs_core::{Budget, Cancellation, Error, ErrorKind, Resources},
    fs_ext_audit::ExtAuditLimits,
    fs_ext_edit::{ExtEditBinding, ExtEditLimits, ExtEditRegion, ExtEditState, ExtEditor},
    fs_undo::{self, UndoBinding, UndoLimits, UndoState},
    io,
    storage::Storage,
};
use std::{cell::RefCell, rc::Rc};
const BASE: usize = 4096;

fn resources() -> Resources {
    Resources {
        memory: Budget::new(2 << 20),
        cancellation: Cancellation::default(),
    }
}
fn l() -> ExtEditLimits {
    ExtEditLimits {
        audit: ExtAuditLimits {
            blocks: 128,
            inodes: 16,
            work: 65536,
            directory_blocks: 4,
            directory_entries: 32,
            findings: 32,
        },
        file_blocks: 32,
        directory_entries: 32,
        affected_bytes: 8192,
        work: 1_000_000,
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

fn put16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}

fn multigroup(bs: usize, sparse: bool) -> (Vec<u8>, u32, u32, Vec<usize>) {
    let first = usize::from(bs == 1024);
    let old = first + 3 * 64 + 48;
    let new = first + 3 * 64 + 60;
    let mut image = vec![0u8; (first + 4 * 64) * bs];
    let mut descriptors = vec![0u8; bs];
    let table_blocks = 2048usize.div_ceil(bs);
    let mut free_total = 0;
    let mut backups = Vec::new();
    let mut root_block = 0;
    let mut file_block = 0;
    let mut table0 = 0;
    for group in 0..4 {
        let start = first + group * 64;
        let backup = !sparse || matches!(group, 0 | 1 | 3);
        if group != 0 && backup {
            backups.push(group);
        }
        let bitmap = start + if backup { 2 } else { 0 };
        let ibitmap = bitmap + 1;
        let table = bitmap + 2;
        let metadata = if backup { 2 } else { 0 } + 2 + table_blocks;
        let allocated = metadata + if group == 0 { 2 } else { 0 };
        let available = if group == 3 { 48 } else { 64 };
        let free = available - allocated;
        free_total += free;
        let at = group * 32;
        put32(&mut descriptors, at, bitmap as u32);
        put32(&mut descriptors, at + 4, ibitmap as u32);
        put32(&mut descriptors, at + 8, table as u32);
        put16(&mut descriptors, at + 12, free as u16);
        put16(&mut descriptors, at + 14, if group == 0 { 5 } else { 16 });
        put16(&mut descriptors, at + 16, u16::from(group == 0));
        descriptors[at + 20] = 0xa0 + group as u8;
        image[bitmap * bs..(bitmap + 1) * bs].fill(255);
        for bit in allocated..available {
            image[bitmap * bs + bit / 8] &= !(1 << (bit % 8));
        }
        image[ibitmap * bs..(ibitmap + 1) * bs].fill(255);
        for bit in if group == 0 { 11 } else { 0 }..16 {
            image[ibitmap * bs + bit / 8] &= !(1 << (bit % 8));
        }
        if group == 0 {
            table0 = table;
            root_block = start + metadata;
            file_block = root_block + 1;
        }
    }
    let mut sb = [0u8; 1024];
    put32(&mut sb, 0, 64);
    put32(&mut sb, 4, old as u32);
    put32(&mut sb, 12, free_total as u32);
    put32(&mut sb, 16, 53);
    put32(&mut sb, 20, first as u32);
    put32(&mut sb, 24, (bs / 1024).trailing_zeros());
    put32(&mut sb, 28, (bs / 1024).trailing_zeros());
    put32(&mut sb, 32, 64);
    put32(&mut sb, 36, 64);
    put32(&mut sb, 40, 16);
    put16(&mut sb, 56, 0xef53);
    put16(&mut sb, 58, 1);
    put32(&mut sb, 76, 1);
    put32(&mut sb, 84, 11);
    put16(&mut sb, 88, 128);
    put32(&mut sb, 96, 2);
    put32(&mut sb, 100, u32::from(sparse));
    sb[104..120].fill(0x39);
    image[1024..2048].copy_from_slice(&sb);
    image[(first + 1) * bs..(first + 2) * bs].copy_from_slice(&descriptors);
    for &group in &backups {
        let at = (first + group * 64) * bs;
        let mut copy = sb;
        put16(&mut copy, 90, group as u16);
        put32(&mut copy, 12, free_total as u32 - 7);
        copy[200] = 0x6b;
        image[at..at + 1024].copy_from_slice(&copy);
        image[at + bs..at + 2 * bs].copy_from_slice(&descriptors);
    }
    let root = table0 * bs + 128;
    let file = table0 * bs + 10 * 128;
    for (at, mode, block) in [(root, 0x41ed, root_block), (file, 0x81a4, file_block)] {
        put16(&mut image, at, mode);
        put32(&mut image, at + 4, bs as u32);
        put16(&mut image, at + 26, 2);
        put32(&mut image, at + 28, (bs / 512) as u32);
        put32(&mut image, at + 40, block as u32);
    }
    for (off, ino, len, name, kind) in [
        (0, 2, 12, b".".as_slice(), 2),
        (12, 2, 12, b"..".as_slice(), 2),
        (24, 11, 16, b"x".as_slice(), 1),
        (40, 11, bs - 40, b"alias".as_slice(), 1),
    ] {
        let at = root_block * bs + off;
        put32(&mut image, at, ino);
        put16(&mut image, at + 4, len as u16);
        image[at + 6] = name.len() as u8;
        image[at + 7] = kind;
        image[at + 8..at + 8 + name.len()].copy_from_slice(name);
    }
    image[file_block * bs..(file_block + 1) * bs].fill(73);
    let mut container = vec![0xa5; BASE + image.len() + BASE];
    container[BASE..BASE + image.len()].copy_from_slice(&image);
    (container, old as u32, new as u32, backups)
}
fn large_limits() -> ExtEditLimits {
    let mut cap = l();
    cap.audit.blocks = 512;
    cap.audit.inodes = 128;
    cap.audit.work = 1_000_000;
    cap.affected_bytes = 65536;
    cap.work = 1_000_000;
    cap.undo.body_bytes = 131072;
    cap.undo.patches = 128;
    cap
}
#[derive(Clone, Copy, Debug)]
enum Kind {
    Read,
    Write(usize),
    Flush,
}
#[derive(Clone, Copy, Debug)]
enum Action {
    Fail(usize),
    Cancel,
}
struct Clock {
    trace: Vec<Kind>,
    cut: Option<usize>,
    action: Action,
    hit: bool,
    cancellation: Cancellation,
    persist_flush: bool,
}
struct Model {
    visible: Vec<u8>,
    durable: Vec<u8>,
    clock: Rc<RefCell<Clock>>,
    immediate: bool,
}
impl Model {
    fn event(&self, kind: Kind) -> Option<Action> {
        let mut c = self.clock.borrow_mut();
        c.trace.push(kind);
        if c.cut == Some(c.trace.len()) {
            c.hit = true;
            Some(c.action)
        } else {
            None
        }
    }
    fn cancel(&self) {
        self.clock.borrow().cancellation.cancel();
    }
    fn cold(&mut self) {
        self.visible.clone_from(&self.durable);
    }
}
impl Storage for Model {
    fn len(&self) -> io::Result<u64> {
        Ok(self.visible.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let action = self.event(Kind::Read);
        if matches!(action, Some(Action::Fail(_))) {
            return Err(io::Error::other("geometry cut read sentinel"));
        }
        out.copy_from_slice(&self.visible[at as usize..at as usize + out.len()]);
        if matches!(action, Some(Action::Cancel)) {
            self.cancel();
        }
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        let action = self.event(Kind::Write(bytes.len()));
        let n = match action {
            Some(Action::Fail(prefix)) => prefix.min(bytes.len()),
            _ => bytes.len(),
        };
        self.visible[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
        if self.immediate {
            self.durable[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
        }
        match action {
            Some(Action::Fail(_)) => Err(io::Error::other("geometry cut write sentinel")),
            Some(Action::Cancel) => {
                self.cancel();
                Ok(n)
            }
            None => Ok(n),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let action = self.event(Kind::Flush);
        if !matches!(action, Some(Action::Fail(_))) || self.clock.borrow().persist_flush {
            self.durable.clone_from(&self.visible);
        }
        match action {
            Some(Action::Fail(_)) => Err(io::Error::other("geometry cut flush sentinel")),
            Some(Action::Cancel) => {
                self.cancel();
                Ok(())
            }
            None => Ok(()),
        }
    }
}
fn clock(r: &Resources) -> Rc<RefCell<Clock>> {
    Rc::new(RefCell::new(Clock {
        trace: Vec::new(),
        cut: None,
        action: Action::Fail(0),
        hit: false,
        cancellation: r.cancellation.clone(),
        persist_flush: false,
    }))
}
fn model(bytes: Vec<u8>, clock: Rc<RefCell<Clock>>, immediate: bool) -> Model {
    Model {
        durable: bytes.clone(),
        visible: bytes,
        clock,
        immediate,
    }
}
fn has_kind(e: &(dyn std::error::Error + 'static), kind: ErrorKind) -> bool {
    if e.downcast_ref::<Error>().is_some_and(|e| e.kind == kind) {
        return true;
    }
    if let Some(e) = e.downcast_ref::<io::Error>()
        && e.get_ref().is_some_and(|e| has_kind(e, kind))
    {
        return true;
    }
    e.source().is_some_and(|e| has_kind(e, kind))
}
fn has_text(e: &(dyn std::error::Error + 'static), text: &str) -> bool {
    if e.to_string() == text {
        return true;
    }
    if let Some(e) = e.downcast_ref::<io::Error>()
        && e.get_ref().is_some_and(|e| has_text(e, text))
    {
        return true;
    }
    e.source().is_some_and(|e| has_text(e, text))
}
#[test]
fn every_growth_target_and_undo_boundary_cold_recovers_exact_images() {
    let started = std::time::Instant::now();
    let mut cases = 0;
    for bs in [1024usize, 2048, 4096] {
        let (before, old, new, _) = multigroup(bs, true);
        let region = ExtEditRegion {
            offset: BASE as u64,
            length: (before.len() - BASE * 2) as u64,
        };
        let limits = large_limits();
        let r = resources();
        let c = clock(&r);
        let mut e = ExtEditor::open(
            model(before.clone(), c.clone(), false),
            model(vec![0; 262144], c.clone(), false),
            region,
            binding(),
            limits,
            &r,
        )
        .unwrap();
        let (batch, _) = e.plan_grow_filesystem(new, &r).unwrap();
        let mut expected = before.clone();
        for p in batch.patches() {
            let at = BASE + p.offset() as usize;
            expected[at..at + p.replacement().len()].copy_from_slice(p.replacement());
        }
        c.borrow_mut().trace.clear();
        e.commit(batch, [0x6a; 16], &r).unwrap();
        let trace = c.borrow().trace.clone();
        let (target, journal, _) = e.into_stores();
        assert_eq!(target.visible, expected);
        drop(target);
        drop(journal);
        assert_eq!(r.memory.used(), 0);
        for (index, kind) in trace.iter().enumerate() {
            let actions = match kind {
                Kind::Write(n) => vec![
                    Action::Fail(0),
                    Action::Fail(n / 2),
                    Action::Fail(*n),
                    Action::Cancel,
                ],
                _ => vec![Action::Fail(0), Action::Cancel],
            };
            for immediate in [false, true] {
                for persist_flush in [false, true] {
                    for action in &actions {
                        cases += 1;
                        let r = resources();
                        let c = clock(&r);
                        let mut e = ExtEditor::open(
                            model(before.clone(), c.clone(), immediate),
                            model(vec![0; 262144], c.clone(), immediate),
                            region,
                            binding(),
                            limits,
                            &r,
                        )
                        .unwrap();
                        let (batch, _) = e.plan_grow_filesystem(new, &r).unwrap();
                        {
                            let mut clock = c.borrow_mut();
                            clock.trace.clear();
                            clock.cut = Some(index + 1);
                            clock.action = *action;
                            clock.persist_flush = persist_flush;
                        }
                        let error = e
                            .commit(batch, [0x6a; 16], &r)
                            .expect_err("actual baseline boundary must fail");
                        assert!(c.borrow().hit);
                        if matches!(action, Action::Cancel) {
                            assert!(has_kind(&error.source, ErrorKind::Cancelled));
                        } else {
                            let sentinel = match kind {
                                Kind::Read => "geometry cut read sentinel",
                                Kind::Write(_) => "geometry cut write sentinel",
                                Kind::Flush => "geometry cut flush sentinel",
                            };
                            assert!(has_text(&error.source, sentinel));
                        }
                        let (mut target, mut journal, state) = e.into_stores();
                        if error.recovery_required {
                            assert_eq!(state, ExtEditState::NeedsRecovery);
                        }
                        target.cold();
                        journal.cold();
                        {
                            let mut clock = c.borrow_mut();
                            clock.cut = None;
                            clock.cancellation = Cancellation::default();
                        }
                        let fresh = resources();
                        let status = fs_undo::inspect(&journal, &fresh);
                        match status {
                            Err(_) => {
                                assert_eq!(
                                    target.visible, before,
                                    "invalid unpublished undo targetchanged at {index}"
                                );
                            }
                            Ok(status) => {
                                let committed = status.state == UndoState::Committed;
                                let recovered = ExtEditor::recover_open(
                                    target,
                                    journal,
                                    region,
                                    UndoBinding {
                                        volume: binding().volume,
                                        generation: binding().generation,
                                        transaction: [0x6a; 16],
                                    },
                                    limits,
                                    &fresh,
                                )
                                .unwrap();
                                assert_eq!(
                                    recovered.geometry().blocks(),
                                    if committed { new } else { old }
                                );
                                assert_eq!(recovered.state(), ExtEditState::Ready);
                                let (target, journal, _) = recovered.into_stores();
                                assert_eq!(
                                    target.visible,
                                    if committed { &expected } else { &before }.to_vec(),
                                    "bs{bs} event{index} {kind:?} {action:?} immediate{immediate} flushpersist{persist_flush}"
                                );
                                drop(target);
                                drop(journal);
                            }
                        }
                        assert_eq!(fresh.memory.used(), 0);
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
        eprintln!(
            "ext2 growth cuts bs={bs} events={} writes={} flushes={} reads={}",
            trace.len(),
            trace.iter().filter(|k| matches!(k, Kind::Write(_))).count(),
            trace.iter().filter(|k| matches!(k, Kind::Flush)).count(),
            trace.iter().filter(|k| matches!(k, Kind::Read)).count()
        );
    }
    eprintln!(
        "ext2 growth cold cases={cases} elapsed={:?}",
        started.elapsed()
    );
}
