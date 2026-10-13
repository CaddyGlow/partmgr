#![cfg(feature = "std")]
// Raw-authored classic EXT3 structure; no builder/private module dependencies.
use partmgr::{
    fs_core::{
        Budget, Cancellation, FileRead, LogicalExtent, NativeName, ObjectId, Resources, Result,
    },
    fs_ext::{ExtJournalLimits, ExtJournalSession, ExtJournalState},
    fs_ext_audit::ExtAuditLimits,
    fs_ext_edit::{ExtCreateMetadata, ExtEditLimits},
    fs_undo::UndoLimits,
    io,
    storage::Storage,
};
use std::{
    cell::Cell,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}
#[derive(Clone)]
enum CallbackFault {
    Backend,
    Cancel(Cancellation),
    ChangedLength,
}
struct Memory {
    lengths: Rc<Cell<usize>>,
    primary_reads: Rc<Cell<usize>>,
    length_fault: Option<(usize, CallbackFault)>,
    primary_fault: Option<usize>,
    bytes: Vec<u8>,
    writes: Rc<Cell<usize>>,
    fail_at: Option<u64>,
}
impl Storage for Memory {
    fn len(&self) -> io::Result<u64> {
        let count = self.lengths.get() + 1;
        self.lengths.set(count);
        if let Some((at, fault)) = &self.length_fault
            && *at == count
        {
            match fault {
                CallbackFault::Backend => {
                    return Err(io::Error::other("public final length backend sentinel"));
                }
                CallbackFault::Cancel(token) => token.cancel(),
                CallbackFault::ChangedLength => return Ok(self.bytes.len() as u64 + 1),
            }
        }
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let n = out.len();
        if at == 1024 && n == 1024 {
            let count = self.primary_reads.get() + 1;
            self.primary_reads.set(count);
            if self.primary_fault == Some(count) {
                return Err(io::Error::other(
                    "public final profile read backend sentinel",
                ));
            }
        }
        out.copy_from_slice(
            self.bytes
                .get(at as usize..at as usize + n)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
        self.writes.set(self.writes.get() + 1);
        if self.fail_at == Some(at) {
            let n = 8.min(b.len());
            self.bytes[at as usize..at as usize + n].copy_from_slice(&b[..n]);
            self.fail_at = None;
            return Err(io::Error::other("public ordered torn suffix sentinel"));
        }
        self.bytes[at as usize..at as usize + b.len()].copy_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn memory(bytes: Vec<u8>) -> Memory {
    Memory {
        lengths: Rc::new(Cell::new(0)),
        primary_reads: Rc::new(Cell::new(0)),
        length_fault: None,
        primary_fault: None,
        bytes,
        writes: Rc::new(Cell::new(0)),
        fail_at: None,
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
        (0, 0xc03b3998),
        (4, 4),
        (12, bs as u32),
        (16, 1024),
        (20, 1),
        (24, 37),
        (64, 1),
    ] {
        put32(j, at, v);
    }
    j[48..64].fill(0x39);
    b
}

fn resources() -> Resources {
    Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ExtJournalLimits {
    ExtJournalLimits {
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
fn input(n: usize) -> Input {
    Input {
        identity: ObjectId {
            source: 999,
            generation: 7,
            native: vec![1],
        },
        bytes: (0..n).map(|i| (i * 17 + 3) as u8).collect(),
    }
}
fn name(n: &[u8]) -> [NativeName; 1] {
    [NativeName::Bytes(n.to_vec())]
}
fn read(s: &ExtJournalSession<Memory>, n: &[u8], r: &Resources) -> Vec<u8> {
    let file = s.file_at(&name(n), &r.cancellation).unwrap();
    let mut bytes = vec![0; usize::try_from(file.len()).unwrap()];
    let count = s.read_at(&file, 0, &mut bytes, &r.cancellation).unwrap();
    bytes.truncate(count);
    bytes
}
#[test]
fn public_ordered_create_append_stale_and_cold_recovery() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let mut s = ExtJournalSession::open(memory(fixture(bs)), limits(), &r).unwrap();
        assert_eq!(s.profile().block_bytes, bs as u32);
        assert_eq!(s.state(), ExtJournalState::Ready);
        let old = s.file_at(&name(b"file"), &r.cancellation).unwrap();
        let initial: Vec<u8> = (0..128).map(|i| i as u8).collect();
        assert_eq!(read(&s, b"file", &r), initial);
        s.create_file(
            &[],
            b"created",
            &ExtCreateMetadata::zeroed(0o100640),
            b"public-created",
            planning(),
            &r.cancellation,
        )
        .unwrap();
        assert_eq!(read(&s, b"created", &r), b"public-created");
        assert!(s.read_at(&old, 0, &mut [0; 1], &r.cancellation).is_err());
        let file = s.file_at(&name(b"file"), &r.cancellation).unwrap();
        let append = input(bs + 17);
        s.append(&file, &append, planning(), &r.cancellation)
            .unwrap();
        let mut expected = initial;
        expected.extend_from_slice(&append.bytes);
        assert_eq!(read(&s, b"file", &r), expected);
        assert!(
            s.append(&file, &append, planning(), &r.cancellation)
                .is_err()
        );
        let (storage, state) = s.into_storage();
        assert_eq!(state, ExtJournalState::Ready);
        let mut cold = ExtJournalSession::open_for_recovery(storage, limits(), &r).unwrap();
        assert_eq!(cold.state(), ExtJournalState::NeedsRecovery);
        assert!(cold.file_at(&name(b"file"), &r.cancellation).is_err());
        cold.recover(&r.cancellation).unwrap();
        assert_eq!(read(&cold, b"file", &r), expected);
        assert_eq!(read(&cold, b"created", &r), b"public-created");
    }
}

#[test]
fn public_namespace_moves_directory_and_releases_indirect_file_in_one_owner() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let original = fixture(bs);
        let original_payload_block = original[31 * bs..32 * bs].to_vec();
        let mut s = ExtJournalSession::open(memory(original), limits(), &r).unwrap();
        assert_eq!(s.profile().version, 7);
        let stale = s.file_at(&name(b"file"), &r.cancellation).unwrap();
        let metadata = ExtCreateMetadata::zeroed(0o40750);
        for directory in [b"left".as_slice(), b"right"] {
            s.create_directory(&[], directory, &metadata, planning(), &r.cancellation)
                .unwrap();
        }
        assert!(s.read_at(&stale, 0, &mut [0; 1], &r.cancellation).is_err());
        drop(stale);
        s.create_directory(
            &name(b"left"),
            b"child",
            &metadata,
            planning(),
            &r.cancellation,
        )
        .unwrap();
        s.rename(
            &name(b"left"),
            b"child",
            &name(b"right"),
            b"moved",
            planning(),
            &r.cancellation,
        )
        .unwrap();
        let moved = [
            NativeName::Bytes(b"right".to_vec()),
            NativeName::Bytes(b"moved".to_vec()),
        ];
        s.rename(&[], b"file", &moved, b"nested", planning(), &r.cancellation)
            .unwrap();
        let path = [
            moved[0].clone(),
            moved[1].clone(),
            NativeName::Bytes(b"nested".to_vec()),
        ];
        let file = s.file_at(&path, &r.cancellation).unwrap();
        let mut bytes = [0; 128];
        assert_eq!(
            s.read_at(&file, 0, &mut bytes, &r.cancellation).unwrap(),
            128
        );
        assert_eq!(bytes, core::array::from_fn(|i| i as u8));
        drop(file);
        let big = input(15 * bs + 73).bytes;
        let mut large_file_plan = planning();
        large_file_plan.affected_bytes = 262144;
        s.create_file(
            &[],
            b"indirect",
            &ExtCreateMetadata::zeroed(0o100640),
            &big,
            large_file_plan,
            &r.cancellation,
        )
        .unwrap();
        let file = s.file_at(&name(b"indirect"), &r.cancellation).unwrap();
        let mut actual = vec![0; big.len()];
        assert_eq!(
            s.read_at(&file, 0, &mut actual, &r.cancellation).unwrap(),
            big.len()
        );
        assert_eq!(actual, big);
        drop(file);
        s.unlink_file(&[], b"indirect", 946684800, planning(), &r.cancellation)
            .unwrap();
        s.rename(&moved, b"nested", &[], b"file", planning(), &r.cancellation)
            .unwrap();
        s.remove_directory(
            &name(b"right"),
            b"moved",
            946684800,
            planning(),
            &r.cancellation,
        )
        .unwrap();
        for directory in [b"left".as_slice(), b"right"] {
            s.remove_directory(&[], directory, 946684800, planning(), &r.cancellation)
                .unwrap();
        }
        let (storage, state) = s.into_storage();
        assert_eq!(state, ExtJournalState::Ready);
        assert_eq!(&storage.bytes[31 * bs..32 * bs], original_payload_block);
        let mut cold = ExtJournalSession::open_for_recovery(storage, limits(), &r).unwrap();
        cold.recover(&r.cancellation).unwrap();
        assert_eq!(
            read(&cold, b"file", &r),
            (0..128).map(|i| i as u8).collect::<Vec<_>>()
        );
        assert!(cold.file_at(&name(b"indirect"), &r.cancellation).is_err());
        drop(cold);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn public_namespace_wrong_kind_nonempty_cycles_and_names_refuse_before_writes() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let backend = memory(fixture(bs));
        let writes = backend.writes.clone();
        let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
        let metadata = ExtCreateMetadata::zeroed(0o40755);
        s.create_directory(&[], b"parent", &metadata, planning(), &r.cancellation)
            .unwrap();
        s.create_directory(
            &name(b"parent"),
            b"child",
            &metadata,
            planning(),
            &r.cancellation,
        )
        .unwrap();
        let before = writes.get();
        assert!(
            s.unlink_file(&[], b"parent", 946684800, planning(), &r.cancellation)
                .is_err()
        );
        assert!(
            s.remove_directory(&[], b"file", 946684800, planning(), &r.cancellation)
                .is_err()
        );
        assert!(
            s.remove_directory(&[], b"parent", 946684800, planning(), &r.cancellation)
                .is_err()
        );
        let child = [
            NativeName::Bytes(b"parent".to_vec()),
            NativeName::Bytes(b"child".to_vec()),
        ];
        assert!(
            s.rename(
                &[],
                b"parent",
                &child,
                b"cycle",
                planning(),
                &r.cancellation
            )
            .is_err()
        );
        assert!(
            s.rename(&[], b"file", &[], b"file", planning(), &r.cancellation)
                .is_err()
        );
        assert!(
            s.rename(&[], b"file", &[], b"parent", planning(), &r.cancellation)
                .is_err()
        );
        for deletion_time in [0, 127] {
            assert!(
                s.unlink_file(&[], b"file", deletion_time, planning(), &r.cancellation)
                    .is_err()
            );
        }
        for bad in [b"".as_slice(), b".", b"..", b"slash/name", b"nul\0name"] {
            assert!(
                s.create_directory(&[], bad, &metadata, planning(), &r.cancellation)
                    .is_err()
            );
        }
        assert_eq!(writes.get(), before);
        assert_eq!(s.state(), ExtJournalState::Ready);
        assert_eq!(
            read(&s, b"file", &r),
            (0..128).map(|i| i as u8).collect::<Vec<_>>()
        );
        drop(s);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn public_unlink_preserves_remaining_hardlink_then_releases_final_inode() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let mut raw = fixture(bs);
        let table = usize::from(bs == 1024) + 4;
        short(&mut raw, table * bs + 10 * 128 + 26, 2);
        short(&mut raw, 30 * bs + 28, 12);
        le(&mut raw, 30 * bs + 36, 11);
        short(&mut raw, 30 * bs + 40, (bs - 36) as u16);
        raw[30 * bs + 42] = 5;
        raw[30 * bs + 43] = 1;
        raw[30 * bs + 44..30 * bs + 49].copy_from_slice(b"alias");
        let payload = raw[31 * bs..32 * bs].to_vec();
        let mut s = ExtJournalSession::open(memory(raw), limits(), &r).unwrap();
        s.unlink_file(&[], b"alias", 946684800, planning(), &r.cancellation)
            .unwrap();
        assert_eq!(
            read(&s, b"file", &r),
            (0..128).map(|i| i as u8).collect::<Vec<_>>()
        );
        s.unlink_file(&[], b"file", 946684800, planning(), &r.cancellation)
            .unwrap();
        assert!(s.file_at(&name(b"file"), &r.cancellation).is_err());
        let (storage, state) = s.into_storage();
        assert_eq!(state, ExtJournalState::Ready);
        assert_eq!(&storage.bytes[31 * bs..32 * bs], payload);
        let cold = ExtJournalSession::open(storage, limits(), &r).unwrap();
        drop(cold);
        assert_eq!(r.memory.used(), 0);
    }
}

// Fill every directory record independently; each residual slot is shorter than
// the 264 bytes needed by a 255-byte name. All filler entries hardlink inode 11.
fn packed_root(bs: usize, blocks: usize) -> Vec<u8> {
    let mut raw = fixture(bs);
    let first = usize::from(bs == 1024);
    let table = (first + 4) * bs;
    let root = table + 128;
    let bitmap = (first + 2) * bs;
    let group = (first + 1) * bs;
    let mut links = 1u16;
    for logical in 0..blocks {
        let physical = if logical == 0 { 30 } else { 1999 + logical };
        le(&mut raw, root + 40 + logical * 4, physical as u32);
        if logical != 0 {
            let bit = physical - first;
            assert_eq!(raw[bitmap + bit / 8] & (1 << (bit % 8)), 0);
            raw[bitmap + bit / 8] |= 1 << (bit % 8);
        }
        let body = &mut raw[physical * bs..(physical + 1) * bs];
        body.fill(0);
        let mut at = 0;
        if logical == 0 {
            for (inode, entry, kind, record) in [
                (2, b".".as_slice(), 2, 12),
                (2, b"..".as_slice(), 2, 12),
                (11, b"file".as_slice(), 1, 12),
            ] {
                le(body, at, inode);
                short(body, at + 4, record);
                body[at + 6] = entry.len() as u8;
                body[at + 7] = kind;
                body[at + 8..at + 8 + entry.len()].copy_from_slice(entry);
                at += usize::from(record);
            }
        }
        while bs - at >= 264 {
            let mut entry = [b'x'; 255];
            entry[..8].copy_from_slice(format!("{links:08}").as_bytes());
            let record = if bs - at < 528 { bs - at } else { 264 };
            le(body, at, 11);
            short(body, at + 4, record as u16);
            body[at + 6] = 255;
            body[at + 7] = 1;
            body[at + 8..at + 263].copy_from_slice(&entry);
            links += 1;
            at += record;
        }
        assert_eq!(at, bs);
    }
    le(&mut raw, root + 4, (blocks * bs) as u32);
    le(&mut raw, root + 28, (blocks * bs / 512) as u32);
    short(&mut raw, table + 10 * 128 + 26, links);
    let extra = (blocks - 1) as u32;
    let free = u32::from_le_bytes(raw[1036..1040].try_into().unwrap()) - extra;
    le(&mut raw, 1036, free);
    let free = u16::from_le_bytes(raw[group + 12..group + 14].try_into().unwrap());
    short(&mut raw, group + 12, free - extra as u16);
    raw
}

fn truncate_fixture(bs: usize, hole: bool) -> (Vec<u8>, Vec<usize>) {
    let mut raw = fixture(bs);
    let first = usize::from(bs == 1024);
    let table = (first + 4) * bs;
    let file = table + 10 * 128;
    let bitmap = (first + 2) * bs;
    let group = (first + 1) * bs;
    let (length, data, indirect) = if hole {
        (3 * bs + 37, vec![31, 2000, 2001, 0], None)
    } else {
        let mut data = vec![31];
        data.extend(2000..2015);
        (15 * bs + 73, data, Some(2015))
    };
    let physical: Vec<_> = data.iter().copied().filter(|block| *block != 0).collect();
    let extra: Vec<_> = physical
        .iter()
        .copied()
        .filter(|block| *block != 31)
        .chain(indirect)
        .collect();
    for block in &extra {
        let bit = block - first;
        assert_eq!(raw[bitmap + bit / 8] & (1 << (bit % 8)), 0);
        raw[bitmap + bit / 8] |= 1 << (bit % 8);
    }
    raw[file + 40..file + 100].fill(0);
    for (logical, block) in data.iter().copied().enumerate() {
        if logical < 12 {
            le(&mut raw, file + 40 + logical * 4, block as u32);
        } else {
            le(
                &mut raw,
                indirect.unwrap() * bs + (logical - 12) * 4,
                block as u32,
            );
        }
        if block != 0 {
            for (index, byte) in raw[block * bs..(block + 1) * bs].iter_mut().enumerate() {
                *byte = ((logical * 47 + index * 29) % 251 + 1) as u8;
            }
        }
    }
    if let Some(block) = indirect {
        le(&mut raw, file + 88, block as u32);
    }
    le(&mut raw, file + 4, length as u32);
    le(
        &mut raw,
        file + 28,
        ((physical.len() + usize::from(indirect.is_some())) * bs / 512) as u32,
    );
    short(&mut raw, file + 26, 2);
    // Add a second independent directory entry to the same inode.
    short(&mut raw, 30 * bs + 28, 12);
    le(&mut raw, 30 * bs + 36, 11);
    short(&mut raw, 30 * bs + 40, (bs - 36) as u16);
    raw[30 * bs + 42] = 5;
    raw[30 * bs + 43] = 1;
    raw[30 * bs + 44..30 * bs + 49].copy_from_slice(b"alias");
    let free = u32::from_le_bytes(raw[1036..1040].try_into().unwrap());
    le(&mut raw, 1036, free - extra.len() as u32);
    let free = u16::from_le_bytes(raw[group + 12..group + 14].try_into().unwrap());
    short(&mut raw, group + 12, free - extra.len() as u16);
    (raw, physical)
}

#[test]
fn public_ordered_truncate_preserves_old_physical_payload_and_updates_every_hardlink() {
    for bs in [1024, 2048, 4096] {
        for (hole, length) in [
            (false, 0),
            (false, 5 * bs),
            (false, 13 * bs),
            (false, 5 * bs + 17),
            (false, 13 * bs + 19),
            (true, 3 * bs + 17),
        ] {
            let (original, physical) = truncate_fixture(bs, hole);
            let first = usize::from(bs == 1024);
            let inode_at = (first + 4) * bs + 10 * 128;
            let r = resources();
            let mut session =
                ExtJournalSession::open(memory(original.clone()), limits(), &r).unwrap();
            assert_eq!(session.profile().version, 7);
            let payload = read(&session, b"file", &r);
            assert_eq!(read(&session, b"alias", &r), payload);
            let stale = session.file_at(&name(b"file"), &r.cancellation).unwrap();
            let mut plan = planning();
            plan.affected_bytes = 262144;
            session
                .truncate(&stale, length as u64, plan, &r.cancellation)
                .unwrap_or_else(|error| panic!("bs={bs} hole={hole} length={length}: {error:?}"));
            assert!(
                session
                    .read_at(&stale, 0, &mut [0], &r.cancellation)
                    .is_err()
            );
            drop(stale);
            assert_eq!(read(&session, b"file", &r), payload[..length]);
            assert_eq!(read(&session, b"alias", &r), payload[..length]);
            let (backend, state) = session.into_storage();
            assert_eq!(state, ExtJournalState::Ready);
            for block in &physical {
                assert_eq!(
                    &backend.bytes[block * bs..(block + 1) * bs],
                    &original[block * bs..(block + 1) * bs]
                );
            }
            for offset in 0..128 {
                if !(4..8).contains(&offset)
                    && !(28..32).contains(&offset)
                    && !(40..100).contains(&offset)
                {
                    assert_eq!(
                        backend.bytes[inode_at + offset],
                        original[inode_at + offset]
                    );
                }
            }
            let cold = ExtJournalSession::open(backend, limits(), &r).unwrap();
            assert_eq!(read(&cold, b"file", &r), payload[..length]);
            assert_eq!(read(&cold, b"alias", &r), payload[..length]);
            drop(cold);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn public_ordered_truncate_refuses_equal_larger_and_foreign_handles_before_writes() {
    let r = resources();
    let backend = memory(fixture(1024));
    let writes = backend.writes.clone();
    let mut owner = ExtJournalSession::open(backend, limits(), &r).unwrap();
    let other = ExtJournalSession::open(memory(fixture(1024)), limits(), &r).unwrap();
    let foreign = other.file_at(&name(b"file"), &r.cancellation).unwrap();
    assert!(
        owner
            .truncate(&foreign, 17, planning(), &r.cancellation)
            .is_err()
    );
    for length in [128, 129, u64::MAX] {
        let file = owner.file_at(&name(b"file"), &r.cancellation).unwrap();
        assert!(
            owner
                .truncate(&file, length, planning(), &r.cancellation)
                .is_err()
        );
    }
    assert_eq!(writes.get(), 0);
    assert_eq!(owner.state(), ExtJournalState::Ready);
    assert_eq!(
        read(&owner, b"file", &r),
        (0..128).map(|byte| byte as u8).collect::<Vec<_>>()
    );
    drop((owner, other, foreign));
    assert_eq!(r.memory.used(), 0);
}

enum GuardFault {
    Backend,
    ChangedSource,
    Cancel(Cancellation),
}
struct GuardFailure {
    inner: Memory,
    source: u64,
    block_bytes: usize,
    reads: Cell<usize>,
    fail_on: usize,
    fault: GuardFault,
}
impl Storage for GuardFailure {
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.inner.read_exact_at(at, out)?;
        if at == self.source && out.len() == self.block_bytes {
            let count = self.reads.get() + 1;
            self.reads.set(count);
            if count == self.fail_on {
                match &self.fault {
                    GuardFault::Backend => {
                        return Err(io::Error::other(
                            "truncate exact source guard backend sentinel",
                        ));
                    }
                    GuardFault::ChangedSource => *out.last_mut().unwrap() ^= 1,
                    GuardFault::Cancel(token) => token.cancel(),
                }
            }
        }
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write_at(at, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
#[test]
fn public_ordered_truncate_source_guards_refuse_changed_bytes_backend_errors_and_cancellation_before_writes()
 {
    for bs in [1024, 2048, 4096] {
        for fail_on in [2, 3] {
            for fault_kind in 0..3 {
                let r = resources();
                let original = fixture(bs);
                let inner = memory(original.clone());
                let writes = inner.writes.clone();
                let fault = match fault_kind {
                    0 => GuardFault::Backend,
                    1 => GuardFault::ChangedSource,
                    _ => GuardFault::Cancel(r.cancellation.clone()),
                };
                let backend = GuardFailure {
                    inner,
                    source: (31 * bs) as u64,
                    block_bytes: bs,
                    reads: Cell::new(0),
                    fail_on,
                    fault,
                };
                let mut owner = ExtJournalSession::open(backend, limits(), &r).unwrap();
                let file = owner.file_at(&name(b"file"), &r.cancellation).unwrap();
                let error = owner
                    .truncate(&file, 17, planning(), &r.cancellation)
                    .unwrap_err();
                assert_eq!(
                    writes.get(),
                    0,
                    "bs={bs} fail_on={fail_on} fault={fault_kind}: {error:?}"
                );
                match fault_kind {
                    0 => assert!(
                        format!("{error:?}")
                            .contains("truncate exact source guard backend sentinel")
                    ),
                    _ => {
                        let cause = error
                            .get_ref()
                            .and_then(|cause| cause.downcast_ref::<partmgr::fs_core::Error>())
                            .unwrap();
                        assert_eq!(
                            cause.kind,
                            if fault_kind == 1 {
                                partmgr::fs_core::ErrorKind::StalePlan
                            } else {
                                partmgr::fs_core::ErrorKind::Cancelled
                            }
                        );
                    }
                }
                drop(file);
                let (backend, _) = owner.into_storage();
                assert_eq!(backend.reads.get(), fail_on);
                assert_eq!(backend.inner.bytes, original);
                drop(backend);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn public_rename_grows_packed_parent_across_direct_and_indirect_boundary() {
    for bs in [1024, 2048, 4096] {
        for blocks in [1, 12] {
            let raw = packed_root(bs, blocks);
            let first = usize::from(bs == 1024);
            let table = (first + 4) * bs;
            let inode = raw[table + 10 * 128..table + 11 * 128].to_vec();
            let payload = raw[31 * bs..32 * bs].to_vec();
            let r = resources();
            let mut admission = limits();
            admission.audit.directory_blocks = 32;
            admission.audit.directory_entries = 256;
            let backend = memory(raw);
            let writes = backend.writes.clone();
            let mut session = ExtJournalSession::open(backend, admission, &r).unwrap();
            let target = [b'z'; 255];
            let mut plan = planning();
            plan.audit = admission.audit;
            plan.directory_entries = 256;
            plan.affected_bytes = 262144;
            plan.file_blocks = blocks;
            let refusal = session
                .rename(&[], b"file", &[], &target, plan, &r.cancellation)
                .unwrap_err();
            let cause = refusal
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<partmgr::fs_core::Error>())
                .unwrap();
            assert_eq!(cause.kind, partmgr::fs_core::ErrorKind::BudgetExhausted);
            assert_eq!(writes.get(), 0);
            assert_eq!(session.state(), ExtJournalState::Ready);
            plan.file_blocks = 32;
            session
                .rename(&[], b"file", &[], &target, plan, &r.cancellation)
                .unwrap();
            assert_eq!(
                read(&session, &target, &r),
                (0..128).map(|v| v as u8).collect::<Vec<_>>()
            );
            let (backend, state) = session.into_storage();
            assert_eq!(state, ExtJournalState::Ready);
            assert_eq!(&backend.bytes[table + 10 * 128..table + 11 * 128], inode);
            assert_eq!(&backend.bytes[31 * bs..32 * bs], payload);
            let root = table + 128;
            assert_eq!(
                u32::from_le_bytes(backend.bytes[root + 4..root + 8].try_into().unwrap()),
                ((blocks + 1) * bs) as u32
            );
            let indirect =
                u32::from_le_bytes(backend.bytes[root + 88..root + 92].try_into().unwrap());
            assert_eq!(indirect != 0, blocks == 12);
            let cold = ExtJournalSession::open(backend, admission, &r).unwrap();
            assert_eq!(read(&cold, &target, &r).len(), 128);
            assert!(cold.file_at(&name(b"file"), &r.cancellation).is_err());
            drop(cold);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn public_partial_invisible_suffix_requires_explicit_owned_recovery() {
    let r = resources();
    let mut backend = memory(fixture(1024));
    backend.fail_at = Some(31 * 1024 + 128);
    let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
    let file = s.file_at(&name(b"file"), &r.cancellation).unwrap();
    let error = s
        .append(&file, &input(1041), planning(), &r.cancellation)
        .unwrap_err();
    assert!(format!("{error:?}").contains("public ordered torn suffix sentinel"));
    assert_eq!(s.state(), ExtJournalState::NeedsRecovery);
    let (storage, state) = s.into_storage();
    assert_eq!(state, ExtJournalState::NeedsRecovery);
    assert_ne!(&storage.bytes[31 * 1024 + 128..31 * 1024 + 136], &[0xa5; 8]);
    let mut cold = ExtJournalSession::open_for_recovery(storage, limits(), &r).unwrap();
    cold.recover(&r.cancellation).unwrap();
    assert_eq!(
        read(&cold, b"file", &r),
        (0..128).map(|i| i as u8).collect::<Vec<_>>()
    );
}
#[test]
fn public_unsupported_profile_has_zero_writes() {
    let r = resources();
    for recovery in [false, true] {
        for (at, value) in [
            (1024 + 76, 2),
            (1024 + 72, 1),
            (1024 + 232, 11),
            (1124, 0),
            (1116, 12),
            (1120, 0x42),
            (100 * 1024 + 40, 8),
            (100 * 1024 + 40, 16),
            (100 * 1024 + 40, 1),
        ] {
            let mut bytes = fixture(1024);
            if at >= 100 * 1024 {
                put32(&mut bytes, at, value);
                if value == 8 || value == 16 {
                    bytes[100 * 1024 + 80] = 4;
                }
            } else {
                le(&mut bytes, at, value);
            }
            let backend = memory(bytes);
            let writes = backend.writes.clone();
            let result = if recovery {
                ExtJournalSession::open_for_recovery(backend, limits(), &r)
            } else {
                ExtJournalSession::open(backend, limits(), &r)
            };
            assert!(
                result.is_err(),
                "admitted offset {at} value {value} recovery {recovery}"
            );
            assert_eq!(writes.get(), 0);
        }
    }
}

#[test]
fn public_clean_open_final_length_callbacks_never_publish_a_cancelled_or_stale_owner() {
    let r = resources();
    let source = memory(fixture(1024));
    let count = source.lengths.clone();
    let reference = ExtJournalSession::open(source, limits(), &r).unwrap();
    let final_length = count.get();
    drop(reference);
    assert_eq!(r.memory.used(), 0);
    for mode in 0..3 {
        let r = resources();
        let mut source = memory(fixture(1024));
        let writes = source.writes.clone();
        source.length_fault = Some((
            final_length,
            match mode {
                0 => CallbackFault::Backend,
                1 => CallbackFault::Cancel(r.cancellation.clone()),
                _ => CallbackFault::ChangedLength,
            },
        ));
        let error = ExtJournalSession::open(source, limits(), &r).err().unwrap();
        match mode {
            0 => assert!(format!("{error:?}").contains("public final length backend sentinel")),
            1 => {
                assert!(r.cancellation.check().is_err());
                assert!(format!("{error:?}").contains("Cancelled"));
            }
            _ => assert!(format!("{error:?}").contains("StalePlan")),
        }
        assert_eq!(writes.get(), 0);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn public_recovery_final_profile_and_length_callbacks_keep_recovery_sticky_and_retryable() {
    let original = fixture(1024);
    let r = resources();
    let mut reference =
        ExtJournalSession::open_for_recovery(memory(original.clone()), limits(), &r).unwrap();
    reference.recover(&r.cancellation).unwrap();
    let (reference, _) = reference.into_storage();
    let final_length = reference.lengths.get();
    let final_primary = reference.primary_reads.get();
    drop(reference);
    assert_eq!(r.memory.used(), 0);
    for mode in 0..4 {
        let r = resources();
        let mut source = memory(original.clone());
        if mode == 3 {
            source.primary_fault = Some(final_primary);
        } else {
            source.length_fault = Some((
                final_length,
                match mode {
                    0 => CallbackFault::Backend,
                    1 => CallbackFault::Cancel(r.cancellation.clone()),
                    _ => CallbackFault::ChangedLength,
                },
            ));
        }
        let mut session = ExtJournalSession::open_for_recovery(source, limits(), &r).unwrap();
        let error = session.recover(&r.cancellation).unwrap_err();
        match mode {
            0 => assert!(format!("{error:?}").contains("public final length backend sentinel")),
            1 => {
                assert!(r.cancellation.check().is_err());
                assert!(format!("{error:?}").contains("Cancelled"));
            }
            2 => assert!(format!("{error:?}").contains("StalePlan")),
            _ => {
                assert!(format!("{error:?}").contains("public final profile read backend sentinel"))
            }
        }
        assert_eq!(session.state(), ExtJournalState::NeedsRecovery);
        assert!(
            session
                .file_at(&name(b"file"), &Cancellation::default())
                .is_err()
        );
        let (mut source, state) = session.into_storage();
        assert_eq!(state, ExtJournalState::NeedsRecovery);
        assert_eq!(source.bytes, original);
        assert_eq!(source.writes.get(), 0);
        source.length_fault = None;
        source.primary_fault = None;
        assert_eq!(r.memory.used(), 0);
        let fresh = resources();
        let mut retry = ExtJournalSession::open_for_recovery(source, limits(), &fresh).unwrap();
        retry.recover(&fresh.cancellation).unwrap();
        assert_eq!(retry.state(), ExtJournalState::Ready);
        assert_eq!(
            read(&retry, b"file", &fresh),
            (0..128).map(|v| v as u8).collect::<Vec<_>>()
        );
        let (source, _) = retry.into_storage();
        assert_eq!(source.bytes, original);
        assert_eq!(source.writes.get(), 0);
        drop(source);
        assert_eq!(fresh.memory.used(), 0);
    }
}

#[test]
fn public_equal_profile_other_owner_and_recovery_generation_handles_are_stale() {
    let r = resources();
    let mut first = ExtJournalSession::open(memory(fixture(1024)), limits(), &r).unwrap();
    let second = ExtJournalSession::open(memory(fixture(1024)), limits(), &r).unwrap();
    assert_eq!(first.profile(), second.profile());
    let old = first.file_at(&name(b"file"), &r.cancellation).unwrap();
    let foreign = second.file_at(&name(b"file"), &r.cancellation).unwrap();
    assert_ne!(old.identity().source, foreign.identity().source);
    assert!(
        first
            .read_at(&foreign, 0, &mut [0; 1], &r.cancellation)
            .is_err()
    );
    assert!(
        first
            .append(&foreign, &input(1), planning(), &r.cancellation)
            .is_err()
    );
    first.recover(&r.cancellation).unwrap();
    assert!(
        first
            .read_at(&old, 0, &mut [0; 1], &r.cancellation)
            .is_err()
    );
    assert!(
        first
            .append(&old, &input(1), planning(), &r.cancellation)
            .is_err()
    );
    assert_eq!(
        read(&first, b"file", &r),
        (0..128).map(|v| v as u8).collect::<Vec<_>>()
    );
    drop((old, foreign));
    let (a, _) = first.into_storage();
    let (b, _) = second.into_storage();
    assert_eq!((a.writes.get(), b.writes.get()), (0, 0));
    drop((a, b));
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn public_hardlink_preserves_inode_allocation_and_entire_payload_then_shares_mutations() {
    for bs in [1024, 2048, 4096] {
        let original = fixture(bs);
        let first = usize::from(bs == 1024);
        let inode_at = (first + 4) * bs + 10 * 128;
        let r = resources();
        let mut s = ExtJournalSession::open(memory(original.clone()), limits(), &r).unwrap();
        assert_eq!(s.profile().version, 7);
        s.hard_link(&[], b"file", &[], b"alias", planning(), &r.cancellation)
            .unwrap();
        let (storage, state) = s.into_storage();
        assert_eq!(state, ExtJournalState::Ready);
        let mut expected_inode = original[inode_at..inode_at + 128].to_vec();
        short(&mut expected_inode, 26, 2);
        assert_eq!(&storage.bytes[inode_at..inode_at + 128], expected_inode);
        assert_eq!(
            &storage.bytes[31 * bs..32 * bs],
            &original[31 * bs..32 * bs]
        );
        assert_eq!(
            &storage.bytes[(first + 3) * bs..(first + 4) * bs],
            &original[(first + 3) * bs..(first + 4) * bs]
        );
        assert_eq!(&storage.bytes[1040..1044], &original[1040..1044]);
        let mut s = ExtJournalSession::open(storage, limits(), &r).unwrap();
        s.create_directory(
            &[],
            b"dest",
            &ExtCreateMetadata::zeroed(0o40750),
            planning(),
            &r.cancellation,
        )
        .unwrap();
        s.hard_link(
            &[],
            b"alias",
            &name(b"dest"),
            b"third",
            planning(),
            &r.cancellation,
        )
        .unwrap();
        let alias = s.file_at(&name(b"alias"), &r.cancellation).unwrap();
        let source = input(19);
        s.append(&alias, &source, planning(), &r.cancellation)
            .unwrap();
        drop(alias);
        let expected = read(&s, b"file", &r);
        assert_eq!(read(&s, b"alias", &r), expected);
        let third_path = [
            NativeName::Bytes(b"dest".to_vec()),
            NativeName::Bytes(b"third".to_vec()),
        ];
        let third = s.file_at(&third_path, &r.cancellation).unwrap();
        let mut contents = vec![0; expected.len() + 1];
        let count = s
            .read_at(&third, 0, &mut contents, &r.cancellation)
            .unwrap();
        assert_eq!(&contents[..count], expected);
        s.truncate(&third, 37, planning(), &r.cancellation).unwrap();
        drop(third);
        assert_eq!(read(&s, b"file", &r), expected[..37]);
        assert_eq!(read(&s, b"alias", &r), expected[..37]);
        s.unlink_file(&[], b"alias", 946684800, planning(), &r.cancellation)
            .unwrap();
        s.unlink_file(
            &name(b"dest"),
            b"third",
            946684800,
            planning(),
            &r.cancellation,
        )
        .unwrap();
        assert_eq!(read(&s, b"file", &r), expected[..37]);
        let (storage, _) = s.into_storage();
        assert_eq!(
            u16::from_le_bytes(
                storage.bytes[inode_at + 26..inode_at + 28]
                    .try_into()
                    .unwrap()
            ),
            1
        );
        let mut s = ExtJournalSession::open(storage, limits(), &r).unwrap();
        s.unlink_file(&[], b"file", 946684800, planning(), &r.cancellation)
            .unwrap();
        let (storage, state) = s.into_storage();
        assert_eq!(state, ExtJournalState::Ready);
        assert_eq!(
            storage.bytes[(first + 3) * bs + 10 / 8] & (1 << (10 % 8)),
            0
        );
        drop(storage);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn public_hardlink_grows_exhausted_direct_and_indirect_parent_without_changing_source() {
    for bs in [1024, 2048, 4096] {
        for blocks in [1, 12] {
            let original = packed_root(bs, blocks);
            let first = usize::from(bs == 1024);
            let table = (first + 4) * bs;
            let r = resources();
            let mut admission = limits();
            admission.audit.directory_blocks = 32;
            admission.audit.directory_entries = 256;
            let mut s = ExtJournalSession::open(memory(original.clone()), admission, &r).unwrap();
            let mut plan = planning();
            plan.directory_entries = 256;
            plan.affected_bytes = 262144;
            plan.file_blocks = 32;
            let target = [b'z'; 255];
            s.hard_link(&[], b"file", &[], &target, plan, &r.cancellation)
                .unwrap();
            assert_eq!(read(&s, &target, &r), read(&s, b"file", &r));
            let (storage, state) = s.into_storage();
            assert_eq!(state, ExtJournalState::Ready);
            let mut inode = original[table + 10 * 128..table + 11 * 128].to_vec();
            let links = u16::from_le_bytes(inode[26..28].try_into().unwrap());
            short(&mut inode, 26, links + 1);
            assert_eq!(&storage.bytes[table + 10 * 128..table + 11 * 128], inode);
            assert_eq!(
                &storage.bytes[31 * bs..32 * bs],
                &original[31 * bs..32 * bs]
            );
            let root = table + 128;
            assert_eq!(
                u32::from_le_bytes(storage.bytes[root + 4..root + 8].try_into().unwrap()),
                ((blocks + 1) * bs) as u32
            );
            assert_eq!(
                u32::from_le_bytes(storage.bytes[root + 88..root + 92].try_into().unwrap()) != 0,
                blocks == 12
            );
            drop(storage);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn public_hardlink_invalid_kind_names_collision_cancel_and_limits_have_zero_writes() {
    for bs in [1024, 2048, 4096] {
        for case in 0..8 {
            let original = fixture(bs);
            let backend = memory(original.clone());
            let writes = backend.writes.clone();
            let r = resources();
            let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
            let mut plan = planning();
            let (source, destination) = match case {
                0 => (b"missing".as_slice(), b"new".as_slice()),
                1 => (b".".as_slice(), b"new".as_slice()),
                2 => (b"file".as_slice(), b"file".as_slice()),
                3 => (b"file".as_slice(), b"bad/name".as_slice()),
                4 => (b"file".as_slice(), b"".as_slice()),
                _ => (b"file".as_slice(), b"new".as_slice()),
            };
            let token = Cancellation::default();
            if case == 5 {
                token.cancel();
            }
            if case == 6 {
                plan.work = 0;
            }
            if case == 7 {
                plan.affected_bytes = 0;
            }
            assert!(
                s.hard_link(&[], source, &[], destination, plan, &token)
                    .is_err()
            );
            assert_eq!(writes.get(), 0);
            assert_eq!(s.state(), ExtJournalState::Ready);
            let (backend, _) = s.into_storage();
            assert_eq!(backend.bytes, original);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

// Give every originally free block to inode 11, including its mapping nodes.
// Allocation is real and reachable; no free-count-only forged audit is used.
fn hardlink_no_free(mut raw: Vec<u8>, bs: usize) -> Vec<u8> {
    let first = usize::from(bs == 1024);
    let bitmap = (first + 2) * bs;
    let free: Vec<_> = (first..2048)
        .filter(|block| {
            let bit = block - first;
            raw[bitmap + bit / 8] & (1 << (bit % 8)) == 0
        })
        .collect();
    let n = bs / 4;
    let mut node_count = 0;
    loop {
        let count = 1 + free.len() - node_count;
        let needed = usize::from(count > 12)
            + if count > 12 + n {
                1 + (count - 12 - n).div_ceil(n)
            } else {
                0
            };
        if needed == node_count {
            break;
        }
        node_count = needed;
    }
    let nodes = &free[..node_count];
    let mut data = vec![31usize];
    data.extend_from_slice(&free[node_count..]);
    let inode = (first + 4) * bs + 10 * 128;
    raw[inode + 40..inode + 100].fill(0);
    le(&mut raw, inode + 4, (data.len() * bs) as u32);
    le(
        &mut raw,
        inode + 28,
        ((data.len() + nodes.len()) * bs / 512) as u32,
    );
    for (index, block) in data.iter().take(12).enumerate() {
        le(&mut raw, inode + 40 + index * 4, *block as u32);
    }
    let mut node = 0;
    if data.len() > 12 {
        let single = nodes[node];
        node += 1;
        raw[single * bs..(single + 1) * bs].fill(0);
        le(&mut raw, inode + 88, single as u32);
        for (index, block) in data.iter().skip(12).take(n).enumerate() {
            le(&mut raw, single * bs + index * 4, *block as u32);
        }
    }
    if data.len() > 12 + n {
        let double = nodes[node];
        node += 1;
        raw[double * bs..(double + 1) * bs].fill(0);
        le(&mut raw, inode + 92, double as u32);
        for (index, chunk) in data[12 + n..].chunks(n).enumerate() {
            let child = nodes[node];
            node += 1;
            raw[child * bs..(child + 1) * bs].fill(0);
            le(&mut raw, double * bs + index * 4, child as u32);
            for (slot, block) in chunk.iter().enumerate() {
                le(&mut raw, child * bs + slot * 4, *block as u32);
            }
        }
    }
    assert_eq!(node, nodes.len());
    for block in free {
        let bit = block - first;
        raw[bitmap + bit / 8] |= 1 << (bit % 8);
    }
    le(&mut raw, 1036, 0);
    short(&mut raw, (first + 1) * bs + 12, 0);
    raw
}

#[test]
fn public_hardlink_zero_free_roomy_parent_succeeds_packed_parent_refuses_without_writes() {
    for bs in [1024, 2048, 4096] {
        for packed in [false, true] {
            let original = hardlink_no_free(
                if packed {
                    packed_root(bs, 1)
                } else {
                    fixture(bs)
                },
                bs,
            );
            let r = resources();
            let backend = memory(original.clone());
            let writes = backend.writes.clone();
            let mut admission = limits();
            admission.file_blocks = 2048;
            admission.audit.directory_entries = 256;
            let mut s = ExtJournalSession::open(backend, admission, &r).unwrap();
            let mut plan = planning();
            plan.file_blocks = 2048;
            plan.directory_entries = 256;
            plan.affected_bytes = 262144;
            let target = [b'z'; 255];
            let result = s.hard_link(&[], b"file", &[], &target, plan, &r.cancellation);
            if packed {
                let error = result.unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("ext2 no audited free blocks available")
                );
                assert_eq!(writes.get(), 0);
            } else {
                result.unwrap();
                assert!(writes.get() > 0);
            }
            let (backend, state) = s.into_storage();
            assert_eq!(state, ExtJournalState::Ready);
            if packed {
                assert_eq!(backend.bytes, original);
            }
            drop(backend);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

// 31,999 actual unique dirents reference the original inode, with a native
// single-indirect directory map. The ownership audit sees every reference.
fn hardlink_boundary_fixture() -> Vec<u8> {
    let bs = 4096;
    let mut raw = fixture(bs);
    let bitmap = 2 * bs;
    let root = 4 * bs + 128;
    let mut physical = Vec::new();
    let mut remaining = 31999usize;
    let mut next_name = 0usize;
    while remaining > 0 {
        let block = if physical.is_empty() {
            30
        } else {
            1123 + physical.len()
        };
        physical.push(block);
        raw[block * bs..(block + 1) * bs].fill(0);
        let mut at = 0;
        if physical.len() == 1 {
            for (offset, label) in [(0, b".".as_slice()), (12, b"..".as_slice())] {
                le(&mut raw, block * bs + offset, 2);
                short(&mut raw, block * bs + offset + 4, 12);
                raw[block * bs + offset + 6] = label.len() as u8;
                raw[block * bs + offset + 7] = 2;
                raw[block * bs + offset + 8..block * bs + offset + 8 + label.len()]
                    .copy_from_slice(label);
            }
            at = 24;
        }
        while remaining > 0 && bs - at >= 12 {
            let label = if next_name == 0 {
                "file".to_string()
            } else {
                format!("{:04x}", next_name - 1)
            };
            assert_eq!(label.len(), 4);
            let record = if remaining == 1 || bs - at < 24 {
                bs - at
            } else {
                12
            };
            le(&mut raw, block * bs + at, 11);
            short(&mut raw, block * bs + at + 4, record as u16);
            raw[block * bs + at + 6] = 4;
            raw[block * bs + at + 7] = 1;
            raw[block * bs + at + 8..block * bs + at + 12].copy_from_slice(label.as_bytes());
            at += record;
            remaining -= 1;
            next_name += 1;
        }
        assert_eq!(at, bs);
    }
    let indirect = 1900;
    raw[indirect * bs..(indirect + 1) * bs].fill(0);
    raw[root + 40..root + 100].fill(0);
    for (index, block) in physical.iter().enumerate() {
        if index < 12 {
            le(&mut raw, root + 40 + 4 * index, *block as u32);
        } else {
            le(&mut raw, indirect * bs + 4 * (index - 12), *block as u32);
        }
    }
    le(&mut raw, root + 88, indirect as u32);
    le(&mut raw, root + 4, (physical.len() * bs) as u32);
    le(
        &mut raw,
        root + 28,
        ((physical.len() + 1) * bs / 512) as u32,
    );
    for block in physical.iter().skip(1).copied().chain([indirect]) {
        assert_eq!(raw[bitmap + block / 8] & (1 << (block % 8)), 0);
        raw[bitmap + block / 8] |= 1 << (block % 8);
    }
    let extra = physical.len() as u32;
    let free = u32::from_le_bytes(raw[1036..1040].try_into().unwrap()) - extra;
    le(&mut raw, 1036, free);
    short(&mut raw, bs + 12, free as u16);
    short(&mut raw, 4 * bs + 10 * 128 + 26, 31999);
    raw
}

#[test]
fn public_hardlink_real_31999_references_admits_32000_then_refuses_another_link() {
    let original = hardlink_boundary_fixture();
    let r = Resources {
        memory: Budget::new(512 << 20),
        cancellation: Cancellation::default(),
    };
    let mut admission = limits();
    admission.file_blocks = 512;
    admission.audit.directory_blocks = 512;
    admission.audit.directory_entries = 40000;
    admission.audit.work = 8_000_000;
    let backend = memory(original);
    let writes = backend.writes.clone();
    let mut s = ExtJournalSession::open(backend, admission, &r).unwrap();
    let mut plan = planning();
    plan.directory_entries = 40000;
    plan.file_blocks = 512;
    plan.work = 6_000_000;
    plan.affected_bytes = 262144;
    s.hard_link(&[], b"file", &[], b"last-link", plan, &r.cancellation)
        .unwrap();
    assert_eq!(read(&s, b"last-link", &r), read(&s, b"file", &r));
    let before = writes.get();
    let error = s
        .hard_link(&[], b"file", &[], b"too-many", plan, &r.cancellation)
        .unwrap_err();
    assert!(format!("{error:?}").contains("Unsupported"));
    assert_eq!(writes.get(), before);
    assert_eq!(s.state(), ExtJournalState::Ready);
    let (backend, _) = s.into_storage();
    assert_eq!(
        u16::from_le_bytes(
            backend.bytes[4 * 4096 + 10 * 128 + 26..4 * 4096 + 10 * 128 + 28]
                .try_into()
                .unwrap()
        ),
        32000
    );
    drop(backend);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn public_write_at_copies_arbitrary_ranges_across_maps_and_preserves_original_physical_bytes() {
    for bs in [1024, 2048, 4096] {
        for hole in [false, true] {
            let (original, physical) = truncate_fixture(bs, hole);
            let length = if hole { 3 * bs + 37 } else { 15 * bs + 73 };
            let ranges = if hole {
                vec![
                    (3 * bs + 1, 17),
                    (2 * bs + bs / 2, bs / 2 + 37),
                    (3 * bs, 37),
                ]
            } else {
                vec![
                    (0, 1),
                    (bs - 3, bs + 19),
                    (11 * bs + 17, 2 * bs + 29),
                    (length - 19, 19),
                    (0, length),
                ]
            };
            for (offset, count) in ranges {
                let r = resources();
                let mut s =
                    ExtJournalSession::open(memory(original.clone()), limits(), &r).unwrap();
                assert_eq!(s.profile().version, 7);
                let mut expected = read(&s, b"file", &r);
                let replacement = input(count);
                expected[offset..offset + count].copy_from_slice(&replacement.bytes);
                let file = s.file_at(&name(b"alias"), &r.cancellation).unwrap();
                let mut plan = planning();
                // Whole-file COW also journals allocation and mapping metadata.
                plan.affected_bytes = 1 << 20;
                plan.work = 1_000_000;
                assert_eq!(
                    s.write_at(&file, offset as u64, &replacement, plan, &r.cancellation)
                        .unwrap(),
                    count as u64
                );
                assert!(s.read_at(&file, 0, &mut [0; 1], &r.cancellation).is_err());
                drop(file);
                assert_eq!(read(&s, b"file", &r), expected);
                assert_eq!(read(&s, b"alias", &r), expected);
                let (storage, state) = s.into_storage();
                assert_eq!(state, ExtJournalState::Ready);
                for block in &physical {
                    assert_eq!(
                        &storage.bytes[block * bs..(block + 1) * bs],
                        &original[block * bs..(block + 1) * bs]
                    );
                }
                let inode = (usize::from(bs == 1024) + 4) * bs + 10 * 128;
                for range in [0..4, 4..28, 32..40, 100..128] {
                    assert_eq!(
                        &storage.bytes[inode + range.start..inode + range.end],
                        &original[inode + range.start..inode + range.end]
                    );
                }
                let cold = ExtJournalSession::open(storage, limits(), &r).unwrap();
                assert_eq!(read(&cold, b"file", &r), expected);
                drop(cold);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

struct RangeInput {
    input: Input,
    mode: usize,
    reads: AtomicUsize,
    cancellation: Cancellation,
}
impl FileRead for RangeInput {
    fn identity(&self) -> &ObjectId {
        self.input.identity()
    }
    fn len(&self) -> u64 {
        self.input.len() + u64::from(self.mode == 3 && self.reads.load(Ordering::Relaxed) != 0)
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        match self.mode {
            0 => Ok(0),
            1 => Err(partmgr::fs_core::Error::new(
                partmgr::fs_core::ErrorKind::InvalidData,
                "range input backend sentinel",
            )),
            2 => Ok(out.len() + 1),
            _ => {
                let n = self.input.read_at(at, out, r)?;
                if self.mode == 4 {
                    self.cancellation.cancel();
                }
                Ok(n)
            }
        }
    }
    fn visit_extents(
        &self,
        r: &Resources,
        f: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.input.visit_extents(r, f)
    }
}

#[test]
fn public_write_at_input_bounds_resources_and_faults_refuse_without_writes() {
    for bs in [1024, 2048, 4096] {
        for case in 0..11 {
            let original = fixture(bs);
            let backend = memory(original.clone());
            let writes = backend.writes.clone();
            let r = resources();
            let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
            let file = s.file_at(&name(b"file"), &r.cancellation).unwrap();
            let input = RangeInput {
                input: input(if case == 5 { 0 } else { 17 }),
                mode: if case < 5 { case } else { 5 },
                reads: AtomicUsize::new(0),
                cancellation: r.cancellation.clone(),
            };
            let offset = match case {
                6 => 120,
                7 => u64::MAX,
                _ => 17,
            };
            let mut plan = planning();
            if case == 8 {
                plan.work = 0;
            }
            if case == 9 {
                plan.affected_bytes = 0;
            }
            if case == 10 {
                plan.undo.patches = 0;
            }
            let error = s
                .write_at(&file, offset, &input, plan, &r.cancellation)
                .unwrap_err();
            if case == 1 {
                assert!(format!("{error:?}").contains("range input backend sentinel"));
            }
            assert_eq!(writes.get(), 0, "case={case} bs={bs} {error:?}");
            drop(file);
            let (backend, _) = s.into_storage();
            assert_eq!(backend.bytes, original);
            drop(backend);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn public_write_at_exact_old_block_guards_keep_backend_change_and_cancel_causes() {
    for bs in [1024, 2048, 4096] {
        for fail_on in [2, 3] {
            for kind in 0..3 {
                let r = resources();
                let original = fixture(bs);
                let inner = memory(original.clone());
                let writes = inner.writes.clone();
                let fault = match kind {
                    0 => GuardFault::Backend,
                    1 => GuardFault::ChangedSource,
                    _ => GuardFault::Cancel(r.cancellation.clone()),
                };
                let backend = GuardFailure {
                    inner,
                    source: (31 * bs) as u64,
                    block_bytes: bs,
                    reads: Cell::new(0),
                    fail_on,
                    fault,
                };
                let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
                let file = s.file_at(&name(b"file"), &r.cancellation).unwrap();
                let error = s
                    .write_at(&file, 17, &input(19), planning(), &r.cancellation)
                    .unwrap_err();
                assert_eq!(
                    writes.get(),
                    0,
                    "bs={bs} fail_on={fail_on} kind={kind}: {error:?}"
                );
                if kind == 0 {
                    assert!(
                        format!("{error:?}")
                            .contains("truncate exact source guard backend sentinel")
                    );
                } else {
                    assert!(format!("{error:?}").contains(if kind == 1 {
                        "StalePlan"
                    } else {
                        "Cancelled"
                    }));
                }
                drop(file);
                let (backend, _) = s.into_storage();
                assert_eq!(backend.inner.bytes, original);
                drop(backend);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn public_write_at_cannot_borrow_replaced_blocks_when_original_free_space_is_empty() {
    for bs in [1024, 2048, 4096] {
        let original = hardlink_no_free(fixture(bs), bs);
        let backend = memory(original.clone());
        let writes = backend.writes.clone();
        let r = resources();
        let mut admission = limits();
        admission.file_blocks = 2048;
        let mut s = ExtJournalSession::open(backend, admission, &r).unwrap();
        let file = s.file_at(&name(b"file"), &r.cancellation).unwrap();
        let mut plan = planning();
        plan.file_blocks = 2048;
        plan.affected_bytes = 262144;
        let error = s
            .write_at(&file, 17, &input(19), plan, &r.cancellation)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ext2 no audited free blocks available")
        );
        assert_eq!(writes.get(), 0);
        assert_eq!(s.state(), ExtJournalState::Ready);
        drop(file);
        let (backend, _) = s.into_storage();
        assert_eq!(backend.bytes, original);
        drop(backend);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn public_write_at_rechecks_original_after_data_durability_and_retains_recovery_obligation() {
    for bs in [1024, 2048, 4096] {
        for kind in 0..3 {
            let r = resources();
            let original = fixture(bs);
            let inner = memory(original.clone());
            let writes = inner.writes.clone();
            let fault = match kind {
                0 => GuardFault::Backend,
                1 => GuardFault::ChangedSource,
                _ => GuardFault::Cancel(r.cancellation.clone()),
            };
            let backend = GuardFailure {
                inner,
                source: (31 * bs) as u64,
                block_bytes: bs,
                reads: Cell::new(0),
                fail_on: 4,
                fault,
            };
            let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
            let file = s.file_at(&name(b"file"), &r.cancellation).unwrap();
            let error = s
                .write_at(&file, 17, &input(19), planning(), &r.cancellation)
                .unwrap_err();
            assert!(writes.get() > 0, "expected post-data failure: {error:?}");
            assert_eq!(s.state(), ExtJournalState::NeedsRecovery);
            drop(file);
            let (backend, _) = s.into_storage();
            assert_eq!(
                &backend.inner.bytes[31 * bs..32 * bs],
                &original[31 * bs..32 * bs]
            );
            let retry = resources();
            let mut cold = ExtJournalSession::open_for_recovery(backend, limits(), &retry).unwrap();
            cold.recover(&retry.cancellation).unwrap();
            assert_eq!(cold.state(), ExtJournalState::Ready);
            let file = cold.file_at(&name(b"file"), &retry.cancellation).unwrap();
            let mut bytes = [0; 129];
            let n = cold
                .read_at(&file, 0, &mut bytes, &retry.cancellation)
                .unwrap();
            assert_eq!(n, 128);
            assert_eq!(&bytes[..128], &original[31 * bs..31 * bs + 128]);
            drop((file, cold));
            assert_eq!(r.memory.used(), 0);
            assert_eq!(retry.memory.used(), 0);
        }
    }
}

struct RangeLengthRace {
    input: Input,
    calls: AtomicUsize,
}
impl FileRead for RangeLengthRace {
    fn identity(&self) -> &ObjectId {
        self.input.identity()
    }
    fn len(&self) -> u64 {
        let n = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        self.input.len() + u64::from(n >= 3)
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        self.input.read_at(at, out, r)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        f: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.input.visit_extents(r, f)
    }
}
#[test]
fn public_write_at_pins_returned_count_across_wrapper_session_and_planner_length_samples() {
    let original = fixture(1024);
    let backend = memory(original.clone());
    let writes = backend.writes.clone();
    let r = resources();
    let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
    let file = s.file_at(&name(b"file"), &r.cancellation).unwrap();
    let source = RangeLengthRace {
        input: input(17),
        calls: AtomicUsize::new(0),
    };
    let error = s
        .write_at(&file, 17, &source, planning(), &r.cancellation)
        .unwrap_err();
    assert!(format!("{error:?}").contains("StalePlan"));
    assert_eq!(writes.get(), 0);
    drop(file);
    let (backend, _) = s.into_storage();
    assert_eq!(backend.bytes, original);
    drop(backend);
    assert_eq!(r.memory.used(), 0);
}

fn sparse_public_fixture(bs: usize, mode: usize) -> (Vec<u8>, Vec<usize>) {
    let first = usize::from(bs == 1024);
    let inode = (first + 4) * bs + 10 * 128;
    match mode {
        0 => {
            let mut raw = fixture(bs);
            let bitmap = (first + 2) * bs;
            let bit = 31 - first;
            raw[bitmap + bit / 8] &= !(1 << (bit % 8));
            raw[inode + 40..inode + 100].fill(0);
            le(&mut raw, inode + 4, 0);
            le(&mut raw, inode + 28, 0);
            let free = u32::from_le_bytes(raw[1036..1040].try_into().unwrap()) + 1;
            le(&mut raw, 1036, free);
            short(&mut raw, (first + 1) * bs + 12, free as u16);
            (raw, vec![])
        }
        1 => {
            let mut raw = fixture(bs);
            le(&mut raw, inode + 4, bs as u32);
            (raw, vec![31])
        }
        2 => truncate_fixture(bs, true),
        3 => {
            let raw = fixture(bs);
            (raw, vec![31])
        }
        4 => {
            let (mut raw, blocks) = truncate_fixture(bs, true);
            let indirect = 2015;
            let bitmap = (first + 2) * bs;
            let bit = indirect - first;
            raw[bitmap + bit / 8] |= 1 << (bit % 8);
            raw[indirect * bs..(indirect + 1) * bs].fill(0);
            le(&mut raw, inode + 88, indirect as u32);
            le(&mut raw, inode + 4, (13 * bs + 37) as u32);
            le(&mut raw, inode + 28, (4 * bs / 512) as u32);
            let free = u32::from_le_bytes(raw[1036..1040].try_into().unwrap()) - 1;
            le(&mut raw, 1036, free);
            short(&mut raw, (first + 1) * bs + 12, free as u16);
            (raw, blocks)
        }
        _ => truncate_fixture(bs, false),
    }
}

#[test]
fn public_sparse_extension_preserves_old_bytes_aliases_and_pointer_topology() {
    for bs in [1024, 2048, 4096] {
        for mode in 0..6 {
            for distant in [false, true] {
                let (original, physical) = sparse_public_fixture(bs, mode);
                let r = resources();
                let mut admission = limits();
                admission.file_blocks = 2048;
                let mut s =
                    ExtJournalSession::open(memory(original.clone()), admission, &r).unwrap();
                assert_eq!(s.profile().version, 7);
                let expected_prefix = read(&s, b"file", &r);
                let old_length = expected_prefix.len();
                let new_length = if distant {
                    (12 + bs / 4 + 2) * bs + 11
                } else {
                    old_length + 17
                };
                let file = s.file_at(&name(b"file"), &r.cancellation).unwrap();
                let mut plan = planning();
                plan.file_blocks = 2048;
                plan.work = 1_000_000;
                s.extend_sparse(&file, new_length as u64, plan, &r.cancellation)
                    .unwrap();
                drop(file);
                let mut expected = expected_prefix;
                expected.resize(new_length, 0);
                assert_eq!(read(&s, b"file", &r), expected);
                if mode >= 2 && mode != 3 {
                    assert_eq!(read(&s, b"alias", &r), expected);
                }
                let (storage, state) = s.into_storage();
                assert_eq!(state, ExtJournalState::Ready);
                for block in &physical {
                    assert_eq!(
                        &storage.bytes[block * bs..(block + 1) * bs],
                        &original[block * bs..(block + 1) * bs]
                    );
                }
                let inode = (usize::from(bs == 1024) + 4) * bs + 10 * 128;
                assert_eq!(
                    &storage.bytes[inode + 28..inode + 32],
                    &original[inode + 28..inode + 32]
                );
                for range in [0..4, 8..28, 32..40, 88..128] {
                    assert_eq!(
                        &storage.bytes[inode + range.start..inode + range.end],
                        &original[inode + range.start..inode + range.end]
                    );
                }
                if mode == 4 {
                    assert_eq!(
                        &storage.bytes[2015 * bs..2016 * bs],
                        &original[2015 * bs..2016 * bs]
                    );
                }
                let cold = ExtJournalSession::open(storage, admission, &r).unwrap();
                assert_eq!(read(&cold, b"file", &r), expected);
                drop(cold);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn public_sparse_extension_zero_free_distinguishes_aligned_hole_and_mapped_eof() {
    for bs in [1024, 2048, 4096] {
        for mode in 0..3 {
            let mut original = hardlink_no_free(fixture(bs), bs);
            let inode = (usize::from(bs == 1024) + 4) * bs + 10 * 128;
            let aligned =
                u32::from_le_bytes(original[inode + 4..inode + 8].try_into().unwrap()) as usize;
            let old_length = match mode {
                0 => aligned,
                1 => aligned + 37,
                _ => aligned - 17,
            };
            le(&mut original, inode + 4, old_length as u32);
            let r = resources();
            let mut admission = limits();
            admission.file_blocks = 2048;
            let backend = memory(original.clone());
            let writes = backend.writes.clone();
            let mut s = ExtJournalSession::open(backend, admission, &r).unwrap();
            let prefix = read(&s, b"file", &r);
            let file = s.file_at(&name(b"file"), &r.cancellation).unwrap();
            let mut plan = planning();
            plan.file_blocks = 2048;
            plan.work = 1_000_000;
            let result = s.extend_sparse(&file, (old_length + 17) as u64, plan, &r.cancellation);
            drop(file);
            if mode == 2 {
                let error = result.unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("ext2 no audited free blocks available")
                );
                assert_eq!(writes.get(), 0);
            } else {
                result.unwrap();
                let mut expected = prefix;
                expected.resize(old_length + 17, 0);
                assert_eq!(read(&s, b"file", &r), expected);
            }
            let (backend, state) = s.into_storage();
            assert_eq!(state, ExtJournalState::Ready);
            if mode == 2 {
                assert_eq!(backend.bytes, original);
            }
            drop(backend);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn public_sparse_extension_bounds_cancellation_and_budgets_are_prewrite() {
    for bs in [1024, 2048, 4096] {
        for case in 0..8 {
            let original = fixture(bs);
            let backend = memory(original.clone());
            let writes = backend.writes.clone();
            let r = resources();
            let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
            let file = s.file_at(&name(b"file"), &r.cancellation).unwrap();
            let mut plan = planning();
            let length = match case {
                0 => 128,
                1 => 17,
                2 => u64::MAX,
                3 => u64::from(u32::MAX),
                _ => 129,
            };
            let token = Cancellation::default();
            if case == 4 {
                token.cancel();
            }
            if case == 5 {
                plan.work = 0;
            }
            if case == 6 {
                plan.file_blocks = 0;
            }
            if case == 7 {
                plan.affected_bytes = 0;
            }
            assert!(s.extend_sparse(&file, length, plan, &token).is_err());
            assert_eq!(writes.get(), 0);
            assert_eq!(s.state(), ExtJournalState::Ready);
            drop(file);
            let (backend, _) = s.into_storage();
            assert_eq!(backend.bytes, original);
            drop(backend);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn public_sparse_extension_exact_source_failures_before_and_after_data_remain_causal() {
    for bs in [1024, 2048, 4096] {
        for fail_on in [2, 3, 4] {
            for kind in 0..3 {
                let original = fixture(bs);
                let r = resources();
                let inner = memory(original.clone());
                let writes = inner.writes.clone();
                let fault = match kind {
                    0 => GuardFault::Backend,
                    1 => GuardFault::ChangedSource,
                    _ => GuardFault::Cancel(r.cancellation.clone()),
                };
                let backend = GuardFailure {
                    inner,
                    source: (31 * bs) as u64,
                    block_bytes: bs,
                    reads: Cell::new(0),
                    fail_on,
                    fault,
                };
                let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
                let file = s.file_at(&name(b"file"), &r.cancellation).unwrap();
                let error = s
                    .extend_sparse(&file, 145, planning(), &r.cancellation)
                    .unwrap_err();
                if kind == 0 {
                    assert!(
                        format!("{error:?}")
                            .contains("truncate exact source guard backend sentinel")
                    );
                } else {
                    assert!(format!("{error:?}").contains(if kind == 1 {
                        "StalePlan"
                    } else {
                        "Cancelled"
                    }));
                }
                if fail_on < 4 {
                    assert_eq!(writes.get(), 0);
                } else {
                    assert!(writes.get() > 0);
                    assert_eq!(s.state(), ExtJournalState::NeedsRecovery);
                }
                drop(file);
                let (backend, _) = s.into_storage();
                assert_eq!(
                    &backend.inner.bytes[31 * bs..32 * bs],
                    &original[31 * bs..32 * bs]
                );
                if fail_on < 4 {
                    assert_eq!(backend.inner.bytes, original);
                    drop(backend);
                } else {
                    let retry = resources();
                    let mut cold =
                        ExtJournalSession::open_for_recovery(backend, limits(), &retry).unwrap();
                    cold.recover(&retry.cancellation).unwrap();
                    let file = cold.file_at(&name(b"file"), &retry.cancellation).unwrap();
                    let mut bytes = [0; 146];
                    let n = cold
                        .read_at(&file, 0, &mut bytes, &retry.cancellation)
                        .unwrap();
                    assert_eq!(n, 128);
                    assert_eq!(&bytes[..128], &original[31 * bs..31 * bs + 128]);
                    drop((file, cold));
                    assert_eq!(retry.memory.used(), 0);
                }
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

// Independently raw-authored type-7 entries and inode/target fields. No symlink
// planner or creation API is used to manufacture replacement/lifecycle inputs.
fn symlink_raw_fixture(bs: usize, target: &[u8], aliases: bool) -> Vec<u8> {
    assert!(!target.is_empty() && target.len() < bs && !target.contains(&0));
    let mut raw = fixture(bs);
    let first = usize::from(bs == 1024);
    let table = (first + 4) * bs;
    let at = table + 11 * 128;
    short(&mut raw, at, 0o120751);
    short(&mut raw, at + 2, 123);
    le(&mut raw, at + 4, target.len() as u32);
    for (off, value) in [(8, 946684811), (12, 946684812), (16, 946684813), (100, 71)] {
        le(&mut raw, at + off, value);
    }
    short(&mut raw, at + 24, 321);
    short(&mut raw, at + 26, if aliases { 2 } else { 1 });
    if target.len() < 60 {
        raw[at + 40..at + 40 + target.len()].copy_from_slice(target);
        raw[at + 40 + target.len()] = 0;
        raw[at + 41 + target.len()..at + 100].fill(0xdd);
    } else {
        le(&mut raw, at + 28, (bs / 512) as u32);
        le(&mut raw, at + 40, 2000);
        raw[2000 * bs..2001 * bs].fill(0xd3);
        raw[2000 * bs..2000 * bs + target.len()].copy_from_slice(target);
        raw[2000 * bs + target.len()] = 0;
        let bit = 2000 - first;
        raw[(first + 2) * bs + bit / 8] |= 1 << (bit % 8);
        let free = u32::from_le_bytes(raw[1036..1040].try_into().unwrap());
        le(&mut raw, 1036, free - 1);
        let gd = (first + 1) * bs;
        let free = u16::from_le_bytes(raw[gd + 12..gd + 14].try_into().unwrap());
        short(&mut raw, gd + 12, free - 1);
    }
    raw[(first + 3) * bs + 11 / 8] |= 1 << (11 % 8);
    le(&mut raw, 1040, 116);
    short(&mut raw, (first + 1) * bs + 14, 116);
    short(&mut raw, 30 * bs + 28, 12);
    for (off, entry, last) in [
        (36, b"link".as_slice(), !aliases),
        (48, b"alias".as_slice(), true),
    ] {
        if off == 48 && !aliases {
            break;
        }
        le(&mut raw, 30 * bs + off, 12);
        short(
            &mut raw,
            30 * bs + off + 4,
            if last { (bs - off) as u16 } else { 12 },
        );
        raw[30 * bs + off + 6] = entry.len() as u8;
        raw[30 * bs + off + 7] = 7;
        raw[30 * bs + off + 8..30 * bs + off + 8 + entry.len()].copy_from_slice(entry);
    }
    raw
}
fn symlink_target_read(
    s: &ExtJournalSession<Memory>,
    path: &[NativeName],
    r: &Resources,
) -> Vec<u8> {
    s.read_symlink(path, &r.cancellation)
        .unwrap()
        .as_slice()
        .to_vec()
}

#[test]
fn public_symlink_independent_sources_cover_four_transitions_aliases_and_native_fields() {
    for bs in [1024, 2048, 4096] {
        for oldlen in [59, 60] {
            for newlen in [59, 60] {
                let old = vec![b'o'; oldlen];
                let mut target = vec![0xfe; newlen];
                target[0] = b'/';
                target[1] = b'.';
                let original = symlink_raw_fixture(bs, &old, true);
                let first = usize::from(bs == 1024);
                let at = (first + 4) * bs + 11 * 128;
                let r = resources();
                let mut s =
                    ExtJournalSession::open(memory(original.clone()), limits(), &r).unwrap();
                assert_eq!(symlink_target_read(&s, &name(b"link"), &r), old);
                assert!(s.file_at(&name(b"link"), &r.cancellation).is_err());
                let stale = s.file_at(&name(b"file"), &r.cancellation).unwrap();
                s.replace_symlink_target(&[], b"link", &target, planning(), &r.cancellation)
                    .unwrap();
                for entry in [b"link".as_slice(), b"alias"] {
                    assert_eq!(symlink_target_read(&s, &name(entry), &r), target);
                }
                assert!(s.read_at(&stale, 0, &mut [0], &r.cancellation).is_err());
                drop(stale);
                let (backend, state) = s.into_storage();
                assert_eq!(state, ExtJournalState::Ready);
                assert_eq!(
                    &backend.bytes[31 * bs..32 * bs],
                    &original[31 * bs..32 * bs]
                );
                if oldlen >= 60 {
                    assert_eq!(
                        &backend.bytes[2000 * bs..2001 * bs],
                        &original[2000 * bs..2001 * bs]
                    );
                }
                for off in 0..128 {
                    if !(4..8).contains(&off)
                        && !(28..32).contains(&off)
                        && !(40..100).contains(&off)
                    {
                        assert_eq!(
                            backend.bytes[at + off],
                            original[at + off],
                            "native field {off}"
                        );
                    }
                }
                assert_eq!(
                    u16::from_le_bytes(backend.bytes[at + 26..at + 28].try_into().unwrap()),
                    2
                );
                assert_eq!(
                    u32::from_le_bytes(backend.bytes[at + 100..at + 104].try_into().unwrap()),
                    71
                );
                if newlen >= 60 {
                    let block =
                        u32::from_le_bytes(backend.bytes[at + 40..at + 44].try_into().unwrap())
                            as usize;
                    assert_ne!(block, 2000);
                    assert_eq!(&backend.bytes[block * bs..block * bs + newlen], target);
                    assert!(
                        backend.bytes[block * bs + newlen..(block + 1) * bs]
                            .iter()
                            .all(|b| *b == 0)
                    );
                }
                let mut cold = ExtJournalSession::open_for_recovery(backend, limits(), &r).unwrap();
                cold.recover(&r.cancellation).unwrap();
                assert_eq!(symlink_target_read(&cold, &name(b"alias"), &r), target);
                drop(cold);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn public_symlink_creation_boundaries_and_unfollowed_lifecycle_remain_manageable() {
    for bs in [1024, 2048, 4096] {
        for len in [1, 59, 60, bs - 1] {
            let original = fixture(bs);
            let r = resources();
            let mut s = ExtJournalSession::open(memory(original.clone()), limits(), &r).unwrap();
            let metadata = ExtCreateMetadata::zeroed(0o120750);
            let target = vec![0xf1; len];
            s.create_symlink(
                &[],
                b"link",
                &target,
                &metadata,
                planning(),
                &r.cancellation,
            )
            .unwrap();
            assert_eq!(s.profile().version, 7);
            assert_eq!(symlink_target_read(&s, &name(b"link"), &r), target);
            s.create_directory(
                &[],
                b"parent",
                &ExtCreateMetadata::zeroed(0o40750),
                planning(),
                &r.cancellation,
            )
            .unwrap();
            s.rename(
                &[],
                b"link",
                &name(b"parent"),
                b"moved",
                planning(),
                &r.cancellation,
            )
            .unwrap();
            let path = [
                NativeName::Bytes(b"parent".to_vec()),
                NativeName::Bytes(b"moved".to_vec()),
            ];
            assert_eq!(symlink_target_read(&s, &path, &r), target);
            assert!(
                s.unlink_file(
                    &name(b"parent"),
                    b"moved",
                    946684800,
                    planning(),
                    &r.cancellation
                )
                .is_err()
            );
            assert!(
                s.hard_link(
                    &name(b"parent"),
                    b"moved",
                    &[],
                    b"forbidden",
                    planning(),
                    &r.cancellation
                )
                .is_err()
            );
            s.unlink_symlink(
                &name(b"parent"),
                b"moved",
                946684800,
                planning(),
                &r.cancellation,
            )
            .unwrap();
            assert!(s.read_symlink(&path, &r.cancellation).is_err());
            s.remove_directory(&[], b"parent", 946684800, planning(), &r.cancellation)
                .unwrap();
            let (backend, _) = s.into_storage();
            assert_eq!(
                &backend.bytes[31 * bs..32 * bs],
                &original[31 * bs..32 * bs]
            );
            let cold = ExtJournalSession::open(backend, limits(), &r).unwrap();
            assert_eq!(read(&cold, b"file", &r).len(), 128);
            drop(cold);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn public_symlink_alias_unlink_and_unfollowed_rename_preserve_opaque_source() {
    for bs in [1024, 2048, 4096] {
        for len in [59, 60] {
            let target = vec![b'.'; len];
            let original = symlink_raw_fixture(bs, &target, true);
            let first = usize::from(bs == 1024);
            let at = (first + 4) * bs + 11 * 128;
            let r = resources();
            let mut s = ExtJournalSession::open(memory(original.clone()), limits(), &r).unwrap();
            s.rename(&[], b"link", &[], b"renamed", planning(), &r.cancellation)
                .unwrap();
            let (backend, _) = s.into_storage();
            assert_eq!(&backend.bytes[at..at + 128], &original[at..at + 128]);
            let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
            s.unlink_symlink(&[], b"renamed", 946684800, planning(), &r.cancellation)
                .unwrap();
            assert_eq!(symlink_target_read(&s, &name(b"alias"), &r), target);
            let (backend, _) = s.into_storage();
            for off in 0..128 {
                if !(26..28).contains(&off) {
                    assert_eq!(backend.bytes[at + off], original[at + off]);
                }
            }
            assert_eq!(
                u16::from_le_bytes(backend.bytes[at + 26..at + 28].try_into().unwrap()),
                1
            );
            let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
            s.unlink_symlink(&[], b"alias", 946684800, planning(), &r.cancellation)
                .unwrap();
            let (backend, _) = s.into_storage();
            assert_eq!(
                u32::from_le_bytes(backend.bytes[at + 20..at + 24].try_into().unwrap()),
                946684800
            );
            assert!(backend.bytes[at + 40..at + 100].iter().all(|b| *b == 0));
            if len >= 60 {
                assert_eq!(
                    &backend.bytes[2000 * bs..2001 * bs],
                    &original[2000 * bs..2001 * bs]
                );
            }
            drop(backend);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn public_symlink_invalid_targets_kinds_collision_and_limits_are_prewrite() {
    for bs in [1024, 2048, 4096] {
        for case in 0..10 {
            let r = resources();
            let original = symlink_raw_fixture(bs, b"dangling", false);
            let backend = memory(original.clone());
            let writes = backend.writes.clone();
            let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
            let metadata = ExtCreateMetadata::zeroed(0o120777);
            let mut plan = planning();
            let error = match case {
                0 => s.create_symlink(&[], b"new", b"", &metadata, plan, &r.cancellation),
                1 => s.create_symlink(&[], b"new", b"a\0b", &metadata, plan, &r.cancellation),
                2 => s.create_symlink(
                    &[],
                    b"new",
                    &vec![b'x'; bs],
                    &metadata,
                    plan,
                    &r.cancellation,
                ),
                3 => s.create_symlink(&[], b"file", b"ok", &metadata, plan, &r.cancellation),
                4 => s.replace_symlink_target(&[], b"file", b"ok", plan, &r.cancellation),
                5 => s.unlink_symlink(&[], b"file", 946684800, plan, &r.cancellation),
                6 => s.replace_symlink_target(&[], b"absent", b"ok", plan, &r.cancellation),
                7 => {
                    plan.work = 1;
                    s.replace_symlink_target(&[], b"link", b"ok", plan, &r.cancellation)
                }
                8 => {
                    plan.affected_bytes = 1;
                    s.create_symlink(&[], b"new", b"ok", &metadata, plan, &r.cancellation)
                }
                _ => {
                    r.cancellation.cancel();
                    s.create_symlink(&[], b"new", b"ok", &metadata, plan, &r.cancellation)
                }
            }
            .unwrap_err();
            assert!(!error.to_string().is_empty());
            assert_eq!(writes.get(), 0);
            assert_eq!(s.state(), ExtJournalState::Ready);
            let (backend, _) = s.into_storage();
            assert_eq!(backend.bytes, original);
            drop(backend);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn public_symlink_packed_parent_growth_and_real_zero_free_distinctions() {
    for bs in [1024, 2048, 4096] {
        for blocks in [1, 12] {
            let original = packed_root(bs, blocks);
            let r = resources();
            let mut admission = limits();
            admission.audit.directory_blocks = 32;
            admission.audit.directory_entries = 256;
            let mut plan = planning();
            plan.directory_entries = 256;
            plan.audit = admission.audit;
            plan.affected_bytes = 262144;
            let mut s = ExtJournalSession::open(memory(original.clone()), admission, &r).unwrap();
            let targetname = [b'z'; 255];
            s.create_symlink(
                &[],
                &targetname,
                b"/unfollowed",
                &ExtCreateMetadata::zeroed(0o120700),
                plan,
                &r.cancellation,
            )
            .unwrap();
            assert_eq!(
                symlink_target_read(&s, &name(&targetname), &r),
                b"/unfollowed"
            );
            let (backend, _) = s.into_storage();
            let root = (usize::from(bs == 1024) + 4) * bs + 128;
            assert_eq!(
                u32::from_le_bytes(backend.bytes[root + 4..root + 8].try_into().unwrap()),
                ((blocks + 1) * bs) as u32
            );
            assert_eq!(
                u32::from_le_bytes(backend.bytes[root + 88..root + 92].try_into().unwrap()) != 0,
                blocks == 12
            );
            assert_eq!(
                &backend.bytes[31 * bs..32 * bs],
                &original[31 * bs..32 * bs]
            );
            drop(backend);
            assert_eq!(r.memory.used(), 0);
        }
        for slow in [false, true] {
            for newslow in [false, true] {
                let original = hardlink_no_free(
                    symlink_raw_fixture(bs, &vec![b'o'; if slow { 60 } else { 59 }], false),
                    bs,
                );
                let r = resources();
                let mut admission = limits();
                admission.file_blocks = 2048;
                let mut plan = planning();
                plan.file_blocks = 2048;
                plan.affected_bytes = 262144;
                let backend = memory(original.clone());
                let writes = backend.writes.clone();
                let mut s = ExtJournalSession::open(backend, admission, &r).unwrap();
                let target = vec![b'n'; if newslow { 60 } else { 59 }];
                let result = s.replace_symlink_target(&[], b"link", &target, plan, &r.cancellation);
                if newslow {
                    assert!(
                        result
                            .unwrap_err()
                            .to_string()
                            .contains("no audited free blocks")
                    );
                    assert_eq!(writes.get(), 0);
                } else {
                    result.unwrap();
                    assert_eq!(symlink_target_read(&s, &name(b"link"), &r), target);
                }
                let (backend, _) = s.into_storage();
                if newslow {
                    assert_eq!(backend.bytes, original);
                }
                if slow {
                    assert_eq!(
                        &backend.bytes[2000 * bs..2001 * bs],
                        &original[2000 * bs..2001 * bs]
                    );
                }
                drop(backend);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

// Arm only after admission; writes distinguish the pre-preparation and
// post-preparation source comparisons without hardcoding decoder read counts.
struct SymlinkGuardBackend {
    inner: Memory,
    source: u64,
    armed: Rc<Cell<bool>>,
    after_writes: bool,
    fired: Rc<Cell<bool>>,
    fault: GuardFault,
}
impl Storage for SymlinkGuardBackend {
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.inner.read_exact_at(at, out)?;
        if self.armed.get()
            && !self.fired.get()
            && at == self.source
            && out.len() >= 1024
            && ((self.inner.writes.get() > 0) == self.after_writes)
        {
            self.fired.set(true);
            match &self.fault {
                GuardFault::Backend => {
                    return Err(io::Error::other("symlink original target backend sentinel"));
                }
                GuardFault::ChangedSource => *out.last_mut().unwrap() ^= 1,
                GuardFault::Cancel(token) => token.cancel(),
            }
        }
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write_at(at, bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
#[test]
fn public_symlink_original_target_guards_keep_causes_and_cold_recovery_obligation() {
    for bs in [1024, 2048, 4096] {
        for after in [false, true] {
            for kind in 0..3 {
                // ChangedSource is targeted at the final comparison, where original
                // slow-body tail bytes are opaque semantically but must match exactly.
                if !after && kind == 1 {
                    continue;
                }
                let original = symlink_raw_fixture(bs, &[b'o'; 60], true);
                let r = resources();
                let inner = memory(original.clone());
                let writes = inner.writes.clone();
                let armed = Rc::new(Cell::new(false));
                let fired = Rc::new(Cell::new(false));
                let fault = match kind {
                    0 => GuardFault::Backend,
                    1 => GuardFault::ChangedSource,
                    _ => GuardFault::Cancel(r.cancellation.clone()),
                };
                let backend = SymlinkGuardBackend {
                    inner,
                    source: (2000 * bs) as u64,
                    armed: armed.clone(),
                    after_writes: after,
                    fired: fired.clone(),
                    fault,
                };
                let mut s = ExtJournalSession::open(backend, limits(), &r).unwrap();
                armed.set(true);
                let error = s
                    .replace_symlink_target(&[], b"link", b"new-fast", planning(), &r.cancellation)
                    .unwrap_err();
                assert!(fired.get());
                assert!(format!("{error:?}").contains(match kind {
                    0 => "symlink original target backend sentinel",
                    1 => "StalePlan",
                    _ => "Cancelled",
                }));
                if after {
                    assert!(writes.get() > 0);
                    assert_eq!(s.state(), ExtJournalState::NeedsRecovery);
                } else {
                    assert_eq!(writes.get(), 0);
                }
                let (backend, _) = s.into_storage();
                assert_eq!(
                    &backend.inner.bytes[2000 * bs..2001 * bs],
                    &original[2000 * bs..2001 * bs]
                );
                assert_eq!(
                    &backend.inner.bytes[31 * bs..32 * bs],
                    &original[31 * bs..32 * bs]
                );
                armed.set(false);
                if after {
                    let retry = resources();
                    let mut cold =
                        ExtJournalSession::open_for_recovery(backend, limits(), &retry).unwrap();
                    cold.recover(&retry.cancellation).unwrap();
                    let target = cold
                        .read_symlink(&name(b"alias"), &retry.cancellation)
                        .unwrap();
                    assert_eq!(target.as_slice(), &[b'o'; 60]);
                    drop(target);
                    drop(cold);
                    assert_eq!(retry.memory.used(), 0);
                } else {
                    assert_eq!(backend.inner.bytes, original);
                    drop(backend);
                }
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn public_symlink_dangling_self_cycles_and_reused_slot_generation_never_follow_targets() {
    for bs in [1024, 2048, 4096] {
        let r = resources();
        let mut s = ExtJournalSession::open(memory(fixture(bs)), limits(), &r).unwrap();
        let meta = ExtCreateMetadata::zeroed(0o120777);
        for (entry, target) in [
            (b"dangling".as_slice(), b"../absent".as_slice()),
            (b"absolute", b"/absent"),
            (b"self", b"self"),
            (b"cycle-a", b"cycle-b"),
            (b"cycle-b", b"cycle-a"),
        ] {
            s.create_symlink(&[], entry, target, &meta, planning(), &r.cancellation)
                .unwrap();
            assert_eq!(symlink_target_read(&s, &name(entry), &r), target);
        }
        s.unlink_symlink(&[], b"dangling", 946684800, planning(), &r.cancellation)
            .unwrap();
        s.create_symlink(&[], b"reused", b"new", &meta, planning(), &r.cancellation)
            .unwrap();
        let (backend, _) = s.into_storage();
        let at = (usize::from(bs == 1024) + 4) * bs + 11 * 128;
        assert_eq!(
            u32::from_le_bytes(backend.bytes[at + 100..at + 104].try_into().unwrap()),
            2
        );
        assert_eq!(
            u16::from_le_bytes(backend.bytes[at + 26..at + 28].try_into().unwrap()),
            1
        );
        let cold = ExtJournalSession::open(backend, limits(), &r).unwrap();
        assert_eq!(symlink_target_read(&cold, &name(b"reused"), &r), b"new");
        assert_eq!(
            symlink_target_read(&cold, &name(b"cycle-a"), &r),
            b"cycle-b"
        );
        drop(cold);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn public_symlink_zero_free_fast_creation_uses_room_and_packed_creation_refuses() {
    for bs in [1024, 2048, 4096] {
        for packed in [false, true] {
            let original = hardlink_no_free(
                if packed {
                    packed_root(bs, 1)
                } else {
                    fixture(bs)
                },
                bs,
            );
            let r = resources();
            let mut admission = limits();
            admission.file_blocks = 2048;
            admission.audit.directory_entries = 256;
            let mut plan = planning();
            plan.file_blocks = 2048;
            plan.directory_entries = 256;
            plan.affected_bytes = 262144;
            let backend = memory(original.clone());
            let writes = backend.writes.clone();
            let mut s = ExtJournalSession::open(backend, admission, &r).unwrap();
            let targetname = [b'z'; 255];
            let result = s.create_symlink(
                &[],
                &targetname,
                b"unfollowed",
                &ExtCreateMetadata::zeroed(0o120777),
                plan,
                &r.cancellation,
            );
            if packed {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("no audited free blocks")
                );
                assert_eq!(writes.get(), 0);
            } else {
                result.unwrap();
                assert_eq!(
                    symlink_target_read(&s, &name(&targetname), &r),
                    b"unfollowed"
                );
            }
            let (backend, _) = s.into_storage();
            if packed {
                assert_eq!(backend.bytes, original);
            }
            drop(backend);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
