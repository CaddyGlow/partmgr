//! Independent ordered-data visibility and publication tests.
use super::*;
use crate::{
    fs_core::{Budget, Cancellation, FileRead, LogicalExtent, ObjectId, Resources, Result},
    fs_ext_audit::ExtAuditLimits,
    fs_ext_edit::{ExtCreateMetadata, ExtEditLimits},
    fs_undo::UndoLimits,
    storage::Storage,
};
use std::cell::{Cell, RefCell};
#[derive(Clone, Debug)]
enum Event {
    Read(u64, usize),
    Write(u64, Vec<u8>),
    Flush,
}
struct Memory {
    length_reads: Cell<usize>,
    read_fault: Option<(u64, Option<Cancellation>)>,
    data_started: Cell<bool>,
    short: Option<usize>,
    bytes: Vec<u8>,
    events: RefCell<Vec<Event>>,
    boundary: usize,
    fault: Option<(usize, usize)>,
}
impl Memory {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            length_reads: Cell::new(0),
            read_fault: None,
            data_started: Cell::new(false),
            short: None,
            bytes,
            events: RefCell::new(Vec::new()),
            boundary: 0,
            fault: None,
        }
    }
}
impl Storage for Memory {
    fn len(&self) -> io::Result<u64> {
        self.length_reads.set(self.length_reads.get() + 1);
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.events.borrow_mut().push(Event::Read(at, out.len()));
        if let Some((tail, token)) = &self.read_fault
            && self.data_started.get()
            && at == *tail / 1024 * 1024
            && out.len() == 1024
        {
            if let Some(token) = token {
                token.cancel();
            } else {
                return Err(io::Error::other("ordered readback backend sentinel"));
            }
        }
        let at = at as usize;
        out.copy_from_slice(
            self.bytes
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.boundary += 1;
        if self
            .read_fault
            .as_ref()
            .is_some_and(|(tail, _)| at == *tail)
        {
            self.data_started.set(true);
        }
        self.events
            .borrow_mut()
            .push(Event::Write(at, bytes.to_vec()));
        if let Some((cut, prefix)) = self.fault
            && cut == self.boundary
        {
            let n = prefix.min(bytes.len());
            self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            return Err(io::Error::other("ordered injected write sentinel"));
        }
        let n = self.short.unwrap_or(bytes.len()).min(bytes.len());
        self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.boundary += 1;
        self.events.borrow_mut().push(Event::Flush);
        if self.fault.is_some_and(|(cut, _)| cut == self.boundary) {
            return Err(io::Error::other("ordered injected flush sentinel"));
        }
        Ok(())
    }
}
fn le(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn short(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
// Complete classic inode and journal map authored independently of planners.
fn fixture(bs: usize) -> Vec<u8> {
    let first = usize::from(bs == 1024);
    let table = first + 4;
    let bitmap = first + 2;
    let ibitmap = bitmap + 1;
    let n = bs / 4;
    let remaining = 1024usize.saturating_sub(12 + n);
    let children = remaining.div_ceil(n);
    let indirect = 1 + if remaining > 0 { 1 + children } else { 0 };
    let mut b = vec![0; 2048 * bs];
    let mut allocated: Vec<usize> = (first..table + 16384usize.div_ceil(bs)).collect();
    allocated.extend([30, 31]);
    allocated.extend(50..50 + indirect);
    allocated.extend(100..1124);
    let free = 2048 - first - allocated.len();
    for (at, v) in [
        (0, 128),
        (4, 2048),
        (12, free as u32),
        (16, 117),
        (20, first as u32),
        (24, (bs / 1024).trailing_zeros()),
        (28, (bs / 1024).trailing_zeros()),
        (32, 2048),
        (36, 2048),
        (40, 128),
        (76, 1),
        (84, 11),
        (92, 4),
        (96, 2),
        (100, 1),
        (224, 8),
    ] {
        le(&mut b, 1024 + at, v);
    }
    for (at, v) in [(56, 0xef53), (58, 1), (88, 128)] {
        short(&mut b, 1024 + at, v);
    }
    b[1128..1144].fill(0x39);
    let gd = (first + 1) * bs;
    for (at, v) in [(0, bitmap), (4, ibitmap), (8, table)] {
        le(&mut b, gd + at, v as u32);
    }
    for (at, v) in [(12, free as u16), (14, 117), (16, 1)] {
        short(&mut b, gd + at, v);
    }
    for physical in allocated {
        let bit = physical - first;
        b[bitmap * bs + bit / 8] |= 1 << (bit % 8);
    }
    for bit in 2048 - first..bs * 8 {
        b[bitmap * bs + bit / 8] |= 1 << (bit % 8);
    }
    for bit in (0..11).chain(128..bs * 8) {
        b[ibitmap * bs + bit / 8] |= 1 << (bit % 8);
    }
    for (ino, mode, size, links, sectors, block) in [
        (2, 0o40755, bs, 2, bs / 512, 30),
        (11, 0o100600, 128, 1, bs / 512, 31),
        (8, 0o100600, 1024 * bs, 1, (1024 + indirect) * bs / 512, 100),
    ] {
        let at = table * bs + (ino - 1) * 128;
        short(&mut b, at, mode);
        le(&mut b, at + 4, size as u32);
        short(&mut b, at + 26, links);
        le(&mut b, at + 28, sectors as u32);
        le(&mut b, at + 40, block);
    }
    let journal = table * bs + 7 * 128;
    for i in 0..12 {
        le(&mut b, journal + 40 + i * 4, 100 + i as u32);
    }
    le(&mut b, journal + 88, 50);
    for i in 0..n.min(1012) {
        le(&mut b, 50 * bs + i * 4, (112 + i) as u32);
    }
    if remaining > 0 {
        le(&mut b, journal + 92, 51);
        for child in 0..children {
            le(&mut b, 51 * bs + 4 * child, (52 + child) as u32);
            for i in 0..n {
                let logical = 12 + n + child * n + i;
                if logical < 1024 {
                    le(&mut b, (52 + child) * bs + i * 4, (100 + logical) as u32);
                }
            }
        }
    }
    for (off, ino, len, name, kind) in [
        (0, 2, 12, b".".as_slice(), 2),
        (12, 2, 12, b"..".as_slice(), 2),
        (24, 11, bs - 24, b"file".as_slice(), 1),
    ] {
        let at = 30 * bs + off;
        le(&mut b, at, ino);
        short(&mut b, at + 4, len as u16);
        b[at + 6] = name.len() as u8;
        b[at + 7] = kind;
        b[at + 8..at + 8 + name.len()].copy_from_slice(name);
    }
    b[31 * bs..32 * bs].fill(0xa5);
    for (i, v) in b[31 * bs..31 * bs + 128].iter_mut().enumerate() {
        *v = i as u8;
    }
    let j = &mut b[100 * bs..100 * bs + 1024];
    for (at, v) in [
        (0, MAGIC),
        (4, 4),
        (12, bs as u32),
        (16, 1024),
        (20, 1),
        (24, 37),
        (40, 17),
        (64, 1),
    ] {
        put32(j, at, v);
    }
    j[48..64].fill(0x39);
    j[80] = 4;
    let sum = crc32c(!0, j);
    put32(j, 252, sum);
    b
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(64 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> session::Limits {
    session::Limits {
        audit: ExtAuditLimits {
            blocks: 4096,
            inodes: 128,
            work: 1_000_000,
            directory_blocks: 8,
            directory_entries: 64,
            findings: 16,
        },
        file_blocks: 64,
        affected_blocks: 64,
        affected_bytes: 1 << 20,
    }
}
fn planning() -> ExtEditLimits {
    ExtEditLimits {
        audit: limits().audit,
        file_blocks: 64,
        directory_entries: 64,
        affected_bytes: 65536,
        work: 400_000,
        undo: UndoLimits {
            patches: 256,
            body_bytes: 262144,
        },
    }
}
struct Input {
    identity: ObjectId,
    bytes: Vec<u8>,
}
impl FileRead for Input {
    fn identity(&self) -> &ObjectId {
        &self.identity
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        let n = out.len().min(self.bytes.len().saturating_sub(at as usize));
        out[..n].copy_from_slice(&self.bytes[at as usize..at as usize + n]);
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
fn append(session: &mut session::Session<Memory>, bs: usize, r: &Resources) -> io::Result<()> {
    let file = session.file(11, &r.cancellation)?;
    let input = Input {
        identity: ObjectId {
            source: 999,
            generation: 7,
            native: vec![1],
        },
        bytes: (0..bs + 17).map(|i| (i * 17 + 3) as u8).collect(),
    };
    session.operate_ordered(
        session::Operation::Extend {
            file: &file,
            input: &input,
        },
        planning(),
        &r.cancellation,
    )
}
fn visible(session: &session::Session<Memory>, r: &Resources) -> Vec<u8> {
    let file = session.file(11, &r.cancellation).unwrap();
    let mut out = vec![0; 8192];
    let n = session
        .read_at(&file, 0, &mut out, &r.cancellation)
        .unwrap();
    out.truncate(n);
    out
}
fn is_commit(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && be32(bytes, 0) == MAGIC && be32(bytes, 4) == 2
}
#[test]
fn ordered_append_fences_data_and_journals_only_metadata_all_block_sizes() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let original = fixture(bs);
        let mut session =
            session::Session::open(Memory::new(original.clone()), limits(), &r).unwrap();
        append(&mut session, bs, &r).unwrap();
        let payload = visible(&session, &r);
        assert_eq!(&payload[..128], &original[31 * bs..31 * bs + 128]);
        assert_eq!(payload.len(), 128 + bs + 17);
        let (storage, state) = session.into_storage();
        assert_eq!(state, session::State::Ready);
        let events = storage.events.borrow();
        let data = events
            .iter()
            .position(|e| matches!(e,Event::Write(at,_)if *at==(31*bs+128) as u64))
            .unwrap();
        let fence=events[..data].iter().rposition(|e|matches!(e,Event::Write(at,b)if *at==u64::from(bs==1024)*bs as u64 && b.len()==bs && super::super::u32le(b,1024%bs+96)&4!=0)).unwrap();
        assert!(
            events[fence + 1..data]
                .iter()
                .any(|e| matches!(e, Event::Flush))
        );
        let commit = events
            .iter()
            .position(|e| matches!(e,Event::Write(_,b)if is_commit(b)&&be32(b,8)==38))
            .unwrap();
        assert!(data < commit);
        let data_writes: Vec<(usize, u64)> = events[..commit]
            .iter()
            .enumerate()
            .filter_map(|(i, e)| match e {
                Event::Write(at, _)
                    if *at == (31 * bs + 128) as u64
                        || original_free(&original, bs, *at as usize) =>
                {
                    Some((i, *at))
                }
                _ => None,
            })
            .collect();
        let last = data_writes.iter().map(|(i, _)| *i).max().unwrap();
        let flush = events[last + 1..commit]
            .iter()
            .position(|e| matches!(e, Event::Flush))
            .map(|n| n + last + 1)
            .unwrap();
        for (_, at) in data_writes {
            let block = at / bs as u64 * bs as u64;
            assert!(
                events[flush + 1..commit]
                    .iter()
                    .any(|e| matches!(e,Event::Read(found,n)if *found==block&&*n==bs)),
                "missing durable data readback"
            );
        }
        drop(events);
        // Retained native log is decoded independently of planner evidence.
        let boot = bootstrap::Bootstrap::read(&storage, 1024, 1_000_000, &r).unwrap();
        let mut geometry = boot.geometry;
        geometry.start = 1;
        geometry.sequence = 37;
        let replay = scan_owned(
            &geometry,
            64,
            1_000_000,
            &r,
            |logical, out| storage.read_exact_at(boot.physical(logical)?, out),
            |destination| boot.destination(destination),
        )
        .unwrap();
        assert_eq!(replay.committed_transactions, 2);
        assert!(!replay.blocks.iter().any(|b| b.destination == 31));
        let first = usize::from(bs == 1024);
        let bitmap = (first + 2) * bs;
        for block in &replay.blocks {
            let bit = block.destination as usize - first;
            assert_ne!(
                original[bitmap + bit / 8] & (1 << (bit % 8)),
                0,
                "originally free data must not appear in journal redo"
            );
        }
        drop((replay, boot));
        drop(storage);
        assert_eq!(r.memory.used(), 0);
    }
}

fn original_free(original: &[u8], bs: usize, position: usize) -> bool {
    let first = usize::from(bs == 1024);
    let block = position / bs;
    if block < first {
        return false;
    }
    let bit = block - first;
    original[(first + 2) * bs + bit / 8] & (1 << (bit % 8)) == 0
}
#[test]
fn ordered_append_every_write_flush_and_torn_prefix_cold_recovers_visible_old_or_complete_new() {
    for bs in [1024, 2048, 4096] {
        let original = fixture(bs);
        let r = resources();
        let mut reference =
            session::Session::open(Memory::new(original.clone()), limits(), &r).unwrap();
        append(&mut reference, bs, &r).unwrap();
        let expected = visible(&reference, &r);
        let (reference, _) = reference.into_storage();
        let boundaries = reference.boundary;
        let traced = reference
            .events
            .borrow()
            .iter()
            .filter(|e| matches!(e, Event::Write(..) | Event::Flush))
            .count();
        assert_eq!(boundaries, traced);
        eprintln!(
            "ordered cut matrix block_bytes={bs} boundaries={boundaries} modeled_cases={}",
            traced * 4
        );
        drop(reference);
        assert_eq!(r.memory.used(), 0);
        for cut in 1..=boundaries {
            for prefix in [0, 1, 511, usize::MAX] {
                let r = resources();
                let mut source = Memory::new(original.clone());
                source.fault = Some((cut, prefix));
                let mut session = session::Session::open(source, limits(), &r).unwrap();
                let error = append(&mut session, bs, &r).unwrap_err();
                assert!(error.to_string().contains("ordered injected"), "{error:?}");
                let (mut source, state) = session.into_storage();
                assert_eq!(state, session::State::NeedsRecovery);
                source.fault = None;
                let mut cold = session::Session::open_for_recovery(source, limits(), &r).unwrap();
                cold.recover(&r.cancellation).unwrap();
                let actual = visible(&cold, &r);
                assert!(
                    actual == original[31 * bs..31 * bs + 128] || actual == expected,
                    "cut {cut} prefix {prefix}"
                );
                let (source, state) = cold.into_storage();
                assert_eq!(state, session::State::Ready);
                // All original non-file allocated home blocks are unchanged, except protocol
                // controls and the metadata which may legitimately take the new outcome.
                // For old visible outcome, inode/table/bitmap bytes must be old. Journal and
                // primary controls have independent recovery checks above.
                if actual.len() == 128 {
                    let bitmap = (usize::from(bs == 1024) + 2) * bs;
                    for block in usize::from(bs == 1024) + 1..100 {
                        if block == 31 || original_free(&original, bs, block * bs) {
                            continue;
                        }
                        assert_eq!(
                            &source.bytes[block * bs..(block + 1) * bs],
                            &original[block * bs..(block + 1) * bs],
                            "old metadata cut {cut} block {block}"
                        );
                    }
                    assert_eq!(
                        &source.bytes[31 * bs..31 * bs + 128],
                        &original[31 * bs..31 * bs + 128]
                    );
                    assert_eq!(
                        &source.bytes[bitmap..bitmap + bs],
                        &original[bitmap..bitmap + bs]
                    );
                }
                drop(source);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn ordered_invalid_and_budget_requests_never_publish_or_write() {
    let r = resources();
    let mut session = session::Session::open(Memory::new(fixture(1024)), limits(), &r).unwrap();
    let invalid_file = session.file(11, &r.cancellation).unwrap();
    let error = session
        .operate_ordered(
            session::Operation::Truncate {
                file: &invalid_file,
                length: 129,
            },
            planning(),
            &r.cancellation,
        )
        .unwrap_err();
    let cause = error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<Error>())
        .unwrap();
    assert_eq!(cause.kind, ErrorKind::InvalidOperation);
    drop(invalid_file);
    let file = session.file(11, &r.cancellation).unwrap();
    let input = Input {
        identity: ObjectId {
            source: 3,
            generation: 0,
            native: vec![],
        },
        bytes: vec![1; 64],
    };
    let mut cap = planning();
    cap.work = 1;
    assert!(
        session
            .operate_ordered(
                session::Operation::Extend {
                    file: &file,
                    input: &input
                },
                cap,
                &r.cancellation
            )
            .is_err()
    );
    drop(file);
    let (storage, state) = session.into_storage();
    assert_eq!(state, session::State::Ready);
    assert_eq!(storage.boundary, 0);
    drop(storage);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn ordered_regular_create_exposes_only_complete_initialized_payload() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let mut session = session::Session::open(Memory::new(fixture(bs)), limits(), &r).unwrap();
        let metadata = ExtCreateMetadata::zeroed(0o100640);
        let payload: Vec<u8> = (0..bs + 19).map(|i| (i * 29 + 7) as u8).collect();
        session
            .operate_ordered(
                session::Operation::CreateFile {
                    parent: &[],
                    name: b"new",
                    metadata: &metadata,
                    payload: &payload,
                },
                planning(),
                &r.cancellation,
            )
            .unwrap();
        let file = session
            .file_at(
                &[crate::fs_core::NativeName::Bytes(b"new".to_vec())],
                &r.cancellation,
            )
            .unwrap();
        let mut actual = vec![0; payload.len() + 1];
        let n = session
            .read_at(&file, 0, &mut actual, &r.cancellation)
            .unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&actual[..n], payload);
        drop(file);
        let (storage, state) = session.into_storage();
        assert_eq!(state, session::State::Ready);
        drop(storage);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn ordered_data_readback_backend_and_callback_cancel_prevent_mutation_commit() {
    for cancel in [false, true] {
        let r = resources();
        let mut source = Memory::new(fixture(1024));
        source.read_fault = Some((
            (31 * 1024 + 128) as u64,
            cancel.then(|| r.cancellation.clone()),
        ));
        let mut session = session::Session::open(source, limits(), &r).unwrap();
        let error = append(&mut session, 1024, &r).unwrap_err();
        if cancel {
            assert!(r.cancellation.check().is_err());
        } else {
            assert!(format!("{error:?}").contains("ordered readback backend sentinel"));
        }
        let (mut source, state) = session.into_storage();
        assert_eq!(state, session::State::NeedsRecovery);
        assert!(
            !source
                .events
                .borrow()
                .iter()
                .any(|e| matches!(e,Event::Write(_,b)if is_commit(b)&&be32(b,8)==38))
        );
        source.read_fault = None;
        let fresh = resources();
        let mut cold = session::Session::open_for_recovery(source, limits(), &fresh).unwrap();
        cold.recover(&fresh.cancellation).unwrap();
        assert_eq!(
            visible(&cold, &fresh),
            (0..128).map(|i| i as u8).collect::<Vec<_>>()
        );
        drop(cold);
        assert_eq!(r.memory.used(), 0);
        assert_eq!(fresh.memory.used(), 0);
    }
}
#[test]
fn ordered_controller_completes_short_backend_writes() {
    let r = resources();
    let mut source = Memory::new(fixture(1024));
    source.short = Some(17);
    let mut session = session::Session::open(source, limits(), &r).unwrap();
    append(&mut session, 1024, &r).unwrap();
    assert_eq!(visible(&session, &r).len(), 128 + 1024 + 17);
    let (_, state) = session.into_storage();
    assert_eq!(state, session::State::Ready);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn ordered_physical_footprint_refusal_occurs_before_any_publication() {
    let r = resources();
    let mut cap = limits();
    cap.affected_bytes = 10_000;
    let mut session = session::Session::open(Memory::new(fixture(1024)), cap, &r).unwrap();
    let file = session.file(11, &r.cancellation).unwrap();
    let input = Input {
        identity: ObjectId {
            source: 999,
            generation: 0,
            native: vec![1],
        },
        bytes: vec![0x36; 3],
    };
    let error = session
        .operate_ordered(
            session::Operation::Extend {
                file: &file,
                input: &input,
            },
            planning(),
            &r.cancellation,
        )
        .unwrap_err();
    assert!(
        format!("{error:?}").contains("JBD2 descriptor publication physical reservation"),
        "{error:?}"
    );
    drop(file);
    let (storage, _) = session.into_storage();
    assert_eq!(storage.boundary, 0);
    assert_eq!(storage.bytes, fixture(1024));
    drop(storage);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn sealed_ordered_controller_binding_mismatch_fails_before_even_length_or_read_io() {
    let r = resources();
    let mut source = Memory::new(fixture(1024));
    let scope = 77;
    let generation = 9;
    let sealed = {
        let (decoder, _proof) =
            super::super::ExtDecoder::open_native_clean(&source, scope, &r).unwrap();
        let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits().audit, &r).unwrap();
        let context = crate::fs_ext_edit::allocation::PlanningContext::native(
            &source,
            decoder.geometry(),
            &audit,
            (scope, generation),
            planning(),
            &r,
        )
        .unwrap();
        let file = context.file_handle(11, &r).unwrap();
        let input = Input {
            identity: ObjectId {
                source: 555,
                generation: 0,
                native: vec![2],
            },
            bytes: vec![0x38; 3],
        };
        let batch = context.plan_extend(&file, &input, &r).unwrap();
        batch
            .into_ordered_patches(scope, generation, planning().work, &r)
            .unwrap()
    };
    let lengths = source.length_reads.get();
    let events = source.events.borrow().len();
    for (bad_scope, bad_generation) in [(scope + 1, generation), (scope, generation + 1)] {
        let error = transaction::commit_ordered(
            &mut source,
            bad_scope,
            bad_generation,
            limits().audit,
            64,
            1 << 20,
            &[],
            &sealed,
            &r,
        )
        .err()
        .unwrap();
        assert!(format!("{error:?}").contains("ordered controller source or generation differs"));
        assert_eq!(source.length_reads.get(), lengths);
        assert_eq!(source.events.borrow().len(), events);
        assert_eq!(source.boundary, 0);
    }
    drop((sealed, source));
    assert_eq!(r.memory.used(), 0);
}

fn namespace_path(name: &[u8]) -> [crate::fs_core::NativeName; 1] {
    [crate::fs_core::NativeName::Bytes(name.to_vec())]
}
fn namespace_operation(
    s: &mut session::Session<Memory>,
    kind: usize,
    r: &Resources,
) -> io::Result<()> {
    let metadata = ExtCreateMetadata::zeroed(0o40755);
    let operation = match kind {
        0 => session::Operation::CreateDirectory {
            parent: &[],
            name: b"dir",
            metadata: &metadata,
        },
        1 => session::Operation::Rename {
            source: &[],
            name: b"file",
            destination: &[],
            new_name: b"renamed",
        },
        2 => session::Operation::Delete {
            parent: &[],
            name: b"dir",
            deletion_time: 946684800,
        },
        _ => unreachable!(),
    };
    s.operate_ordered(operation, planning(), &r.cancellation)
}
fn namespace_homes_equal(a: &[u8], b: &[u8], bs: usize) -> bool {
    a.len() == b.len()
        && a.chunks_exact(bs)
            .zip(b.chunks_exact(bs))
            .enumerate()
            .all(|(block, (a, b))| (100..1124).contains(&block) || a == b)
}
#[test]
fn ordered_namespace_all_block_sizes_moves_directories_and_refuses_cycles_collisions() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let original = fixture(bs);
        let mut s = session::Session::open(Memory::new(original.clone()), limits(), &r).unwrap();
        namespace_operation(&mut s, 0, &r).unwrap();
        let dir = namespace_path(b"dir");
        let child = ExtCreateMetadata::zeroed(0o40755);
        s.operate_ordered(
            session::Operation::CreateDirectory {
                parent: &dir,
                name: b"child",
                metadata: &child,
            },
            planning(),
            &r.cancellation,
        )
        .unwrap();
        let filemeta = ExtCreateMetadata::zeroed(0o100600);
        s.operate_ordered(
            session::Operation::CreateFile {
                parent: &dir,
                name: b"empty",
                metadata: &filemeta,
                payload: b"",
            },
            planning(),
            &r.cancellation,
        )
        .unwrap();
        s.operate_ordered(
            session::Operation::Rename {
                source: &[],
                name: b"file",
                destination: &dir,
                new_name: b"moved",
            },
            planning(),
            &r.cancellation,
        )
        .unwrap();
        let moved = [dir[0].clone(), namespace_path(b"moved")[0].clone()];
        let file = s.file_at(&moved, &r.cancellation).unwrap();
        let mut bytes = [0; 128];
        assert_eq!(
            s.read_at(&file, 0, &mut bytes, &r.cancellation).unwrap(),
            128
        );
        assert_eq!(&bytes, &original[31 * bs..31 * bs + 128]);
        drop(file);
        let destination = [dir[0].clone(), namespace_path(b"child")[0].clone()];
        assert!(
            s.operate_ordered(
                session::Operation::Rename {
                    source: &[],
                    name: b"dir",
                    destination: &destination,
                    new_name: b"cycle"
                },
                planning(),
                &r.cancellation
            )
            .is_err()
        );
        assert_eq!(s.state(), session::State::Ready);
        assert!(
            s.operate_ordered(
                session::Operation::Rename {
                    source: &dir,
                    name: b"moved",
                    destination: &dir,
                    new_name: b"empty"
                },
                planning(),
                &r.cancellation
            )
            .is_err()
        );
        assert_eq!(s.state(), session::State::Ready);
        s.operate_ordered(
            session::Operation::Rename {
                source: &dir,
                name: b"moved",
                destination: &[],
                new_name: b"file",
            },
            planning(),
            &r.cancellation,
        )
        .unwrap();
        s.operate_ordered(
            session::Operation::Rename {
                source: &[],
                name: b"dir",
                destination: &[],
                new_name: b"other",
            },
            planning(),
            &r.cancellation,
        )
        .unwrap();
        let other = namespace_path(b"other");
        for name in [b"empty".as_slice(), b"child".as_slice()] {
            s.operate_ordered(
                session::Operation::Delete {
                    parent: &other,
                    name,
                    deletion_time: 946684800,
                },
                planning(),
                &r.cancellation,
            )
            .unwrap();
        }
        s.operate_ordered(
            session::Operation::Delete {
                parent: &[],
                name: b"other",
                deletion_time: 946684800,
            },
            planning(),
            &r.cancellation,
        )
        .unwrap();
        assert_eq!(visible(&s, &r), original[31 * bs..31 * bs + 128]);
        let (storage, state) = s.into_storage();
        assert_eq!(state, session::State::Ready);
        assert_eq!(
            &storage.bytes[31 * bs..32 * bs],
            &original[31 * bs..32 * bs]
        );
        drop(storage);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn ordered_namespace_every_write_flush_prefix_cold_recovery_exact_old_or_new_homes() {
    for bs in [1024, 2048, 4096] {
        for kind in 0..3 {
            let r = resources();
            let mut base = fixture(bs);
            if kind == 2 {
                let mut setup = session::Session::open(Memory::new(base), limits(), &r).unwrap();
                namespace_operation(&mut setup, 0, &r).unwrap();
                base = setup.into_storage().0.bytes;
            }
            let mut reference =
                session::Session::open(Memory::new(base.clone()), limits(), &r).unwrap();
            namespace_operation(&mut reference, kind, &r).unwrap();
            let (reference, _) = reference.into_storage();
            let events: Vec<usize> = reference
                .events
                .borrow()
                .iter()
                .filter_map(|event| match event {
                    Event::Write(_, bytes) => Some(bytes.len()),
                    Event::Flush => Some(0),
                    _ => None,
                })
                .collect();
            assert_eq!(events.len(), reference.boundary);
            let expected = reference.bytes;
            assert!(!namespace_homes_equal(&base, &expected, bs));
            eprintln!(
                "ordered namespace bs={bs} kind={kind} boundaries={} cases={}",
                events.len(),
                events.len() * 3
            );
            for (event, size) in events.iter().enumerate() {
                for prefix in [0, size / 2, *size] {
                    let r = resources();
                    let mut backend = Memory::new(base.clone());
                    backend.fault = Some((event + 1, prefix));
                    let mut s = session::Session::open(backend, limits(), &r).unwrap();
                    let error = namespace_operation(&mut s, kind, &r).unwrap_err();
                    assert!(error.to_string().contains("ordered injected"), "{error:?}");
                    let (mut backend, state) = s.into_storage();
                    assert_eq!(state, session::State::NeedsRecovery);
                    backend.fault = None;
                    let mut cold =
                        session::Session::open_for_recovery(backend, limits(), &r).unwrap();
                    cold.recover(&r.cancellation).unwrap();
                    assert_eq!(visible(&cold, &r), base[31 * bs..31 * bs + 128]);
                    let (backend, state) = cold.into_storage();
                    assert_eq!(state, session::State::Ready);
                    let old = namespace_homes_equal(&backend.bytes, &base, bs);
                    let new = namespace_homes_equal(&backend.bytes, &expected, bs);
                    assert_ne!(
                        old,
                        new,
                        "bs={bs} kind={kind} event={} prefix={prefix}",
                        event + 1
                    );
                    assert_eq!(&backend.bytes[31 * bs..32 * bs], &base[31 * bs..32 * bs]);
                    drop(backend);
                    assert_eq!(r.memory.used(), 0);
                }
            }
        }
    }
}

#[test]
fn ordered_namespace_destination_guard_rejects_payload_budget_and_cancel_without_writes() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let source = Memory::new(fixture(bs));
        let (decoder, proof) =
            super::super::ExtDecoder::open_native_clean(&source, 77, &r).unwrap();
        let payload = ReplayBlock {
            destination: 31,
            bytes: [0; MAX_BLOCK],
        };
        let error =
            transaction::validate_namespace_destinations(&decoder, &[payload], 64, 400_000, &r)
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("original regular-file payload"));
        let directory = ReplayBlock {
            destination: 30,
            bytes: [0; MAX_BLOCK],
        };
        transaction::validate_namespace_destinations(
            &decoder,
            core::slice::from_ref(&directory),
            64,
            400_000,
            &r,
        )
        .unwrap();
        let error = transaction::validate_namespace_destinations(
            &decoder,
            core::slice::from_ref(&directory),
            64,
            1,
            &r,
        )
        .unwrap_err();
        assert!(error.to_string().contains("validation work ceiling"));
        let cause = error
            .get_ref()
            .and_then(|e| e.downcast_ref::<crate::fs_core::Error>())
            .unwrap();
        assert_eq!(cause.kind, crate::fs_core::ErrorKind::BudgetExhausted);
        r.cancellation.cancel();
        let error =
            transaction::validate_namespace_destinations(&decoder, &[directory], 64, 400_000, &r)
                .unwrap_err();
        let cause = error
            .get_ref()
            .and_then(|e| e.downcast_ref::<crate::fs_core::Error>())
            .unwrap();
        assert_eq!(cause.kind, crate::fs_core::ErrorKind::Cancelled);
        assert_eq!(source.boundary, 0);
        assert!(
            !source
                .events
                .borrow()
                .iter()
                .any(|e| matches!(e, Event::Write(..) | Event::Flush))
        );
        drop((decoder, proof));
        drop(source);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn sealed_overwrite_guard_is_bound_and_wrong_controller_owner_performs_zero_io() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let mut source = Memory::new(fixture(bs));
        let original = source.bytes.clone();
        let scope = 107;
        let generation = 13;
        let sealed = {
            let (decoder, _proof) =
                super::super::ExtDecoder::open_native_clean(&source, scope, &r).unwrap();
            let audit = crate::fs_ext_audit::audit_decoder(&decoder, limits().audit, &r).unwrap();
            let context = crate::fs_ext_edit::allocation::PlanningContext::native(
                &source,
                decoder.geometry(),
                &audit,
                (scope, generation),
                planning(),
                &r,
            )
            .unwrap();
            let file = context.file_handle(11, &r).unwrap();
            let input = Input {
                identity: ObjectId {
                    source: 556,
                    generation: 0,
                    native: vec![3],
                },
                bytes: vec![0x91; 3],
            };
            let batch = context
                .plan_overwrite_ordered(&file, 1, &input, &r)
                .unwrap();
            batch
                .into_ordered_patches(scope, generation, planning().work, &r)
                .unwrap()
        };
        assert!(sealed.is_overwrite());
        let guards: Vec<_> = sealed.source_guards().collect();
        assert_eq!(guards.len(), 1);
        assert_eq!(guards[0].0, 31 * bs as u64);
        assert_eq!(guards[0].1, &original[31 * bs..32 * bs]);
        drop(guards);
        let lengths = source.length_reads.get();
        let events = source.events.borrow().len();
        for (bad_scope, bad_generation) in [(scope + 1, generation), (scope, generation + 1)] {
            let error = transaction::commit_ordered(
                &mut source,
                bad_scope,
                bad_generation,
                limits().audit,
                64,
                1 << 20,
                &[],
                &sealed,
                &r,
            )
            .err()
            .unwrap();
            assert!(
                format!("{error:?}").contains("ordered controller source or generation differs")
            );
            assert_eq!(source.length_reads.get(), lengths);
            assert_eq!(source.events.borrow().len(), events);
            assert_eq!(source.boundary, 0);
            assert_eq!(source.bytes, original);
        }
        drop((sealed, source));
        assert_eq!(r.memory.used(), 0);
    }
}
