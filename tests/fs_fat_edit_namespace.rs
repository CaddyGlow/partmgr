//! Fixtures assemble native boot/FAT/slot bytes independently of production writers.
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, NativeName, Resources},
    fs_fat_audit::FatAuditLimits,
    fs_fat_edit::{
        FatCreateMetadata, FatEditBatch, FatEditBinding, FatEditLimits, FatEditName, FatEditRegion,
        FatEditState, FatEditor, FatNamePolicy, FatNamespaceOperation,
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
// Same explicit short-write/failed-flush model as range tests, independently scoped here.
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

fn set_fat(b: &mut [u8], copy: usize, n: usize, value: u16) {
    let at = 512 + copy * 512 + n * 3 / 2;
    let old = u16::from_le_bytes([b[at], b[at + 1]]);
    let new = if n & 1 == 0 {
        (old & 0xf000) | (value & 0xfff)
    } else {
        (old & 15) | ((value & 0xfff) << 4)
    };
    w(b, at, new);
}
fn short(alias: &[u8; 11], cluster: u16, len: u32, attrs: u8) -> [u8; 32] {
    let mut r = [0; 32];
    r[..11].copy_from_slice(alias);
    r[11] = attrs;
    w(&mut r, 26, cluster);
    d(&mut r, 28, len);
    r
}
fn fixture(full: bool) -> Vec<u8> {
    let mut b = vec![0; LENGTH];
    b[..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
    w(&mut b, 11, 512);
    b[13] = 1;
    w(&mut b, 14, 1);
    b[16] = 2;
    w(&mut b, 17, 16);
    w(&mut b, 19, 128);
    b[21] = 0xf8;
    w(&mut b, 22, 1);
    w(&mut b, 510, 0xaa55);
    for copy in 0..2 {
        for (n, v) in [
            (0, 0xff8),
            (1, 0xfff),
            (2, 3),
            (3, 0xfff),
            (4, 0xfff),
            (5, 0xfff),
            (6, 0xfff),
        ] {
            set_fat(&mut b, copy, n, v);
        }
    }
    for (i, r) in [
        short(b"PAYLOAD BIN", 2, 600, 32),
        short(b"KEEP    BIN", 4, 7, 32),
        short(b"PARENT     ", 5, 0, 16),
    ]
    .iter()
    .enumerate()
    {
        b[1536 + i * 32..1536 + (i + 1) * 32].copy_from_slice(r);
    }
    for (i, byte) in b[2048..2648].iter_mut().enumerate() {
        *byte = ((i * 31 + 5) % 251) as u8;
    }
    b[2648..3072].fill(0xa7);
    b[3072..3079].copy_from_slice(b"keep!!!");
    for (i, r) in [
        short(b".          ", 5, 0, 16),
        short(b"..         ", 0, 0, 16),
        short(b"NESTED  BIN", 6, 5, 32),
    ]
    .iter()
    .enumerate()
    {
        b[3584 + i * 32..3584 + (i + 1) * 32].copy_from_slice(r);
    }
    b[4096..4101].copy_from_slice(b"inner");
    if full {
        for i in 3..16 {
            let alias = format!("E{i:07}BIN");
            b[3584 + i * 32..3584 + (i + 1) * 32].copy_from_slice(&short(
                alias.as_bytes().try_into().unwrap(),
                0,
                0,
                32,
            ));
        }
    }
    // All unallocated data is poisoned, so complete cluster/tail initialization is observable.
    b[4608..].fill(0x6d);
    let mut c = vec![0xa5; BASE];
    c.extend(b);
    c.extend([0x5a; 2048]);
    c
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
            entries: 64,
            directory_slots: 64,
            findings: 16,
        },
        file_clusters: 512,
        affected_bytes: 8192,
        replacements: 8,
        work: 65536,
        undo: UndoLimits {
            patches: 128,
            body_bytes: 65536,
        },
    }
}
fn binding() -> FatEditBinding {
    FatEditBinding {
        volume: [37; 32],
        generation: 9,
    }
}
fn undo_binding() -> UndoBinding {
    UndoBinding {
        volume: [37; 32],
        generation: 9,
        transaction: [8; 16],
    }
}
fn region() -> FatEditRegion {
    FatEditRegion {
        offset: BASE as u64,
        length: LENGTH as u64,
    }
}
fn native(alias: &[u8; 11]) -> NativeName {
    NativeName::Bytes(alias.to_vec())
}
fn name(alias: &[u8; 11], long: Option<&str>) -> FatEditName {
    FatEditName {
        alias: *alias,
        long_name: long.map(|s| s.encode_utf16().collect()),
        policy: FatNamePolicy::AsciiCaseInsensitive,
    }
}
fn editor(seed: &[u8], clock: Arc<Mutex<Clock>>, r: &Resources) -> FatEditor<Model, Model> {
    FatEditor::open(
        Model::new(seed.to_vec(), clock.clone()),
        Model::new(vec![0; 65536], clock),
        region(),
        binding(),
        limits(),
        r,
    )
    .unwrap()
}
fn bytes(e: &FatEditor<Model, Model>, path: &[NativeName], r: &Resources) -> Vec<u8> {
    let f = e.open_file(path, r).unwrap();
    let mut b = vec![0; f.len() as usize];
    assert_eq!(e.read_at(&f, 0, &mut b, r).unwrap(), b.len());
    b
}
#[test]
fn create_exact_vfat_file_directory_move_delete_and_generation() {
    let r = resources();
    let mut e = editor(&fixture(false), Arc::new(Mutex::new(Clock::default())), &r);
    let root = e.open_directory(&[], &r).unwrap();
    let n = name(b"CREATED BIN", Some("created long.bin"));
    let meta = FatCreateMetadata::zeroed(32);
    let b = e
        .plan_create_file(&root, &n, &meta, &[0x42; 700], &r)
        .unwrap();
    assert_eq!(
        b.namespace_report().unwrap().operation,
        FatNamespaceOperation::CreateFile
    );
    e.commit(b, [8; 16], &r).unwrap();
    assert_eq!(
        e.plan_delete(&root, &native(b"KEEP    BIN"), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::StalePlan
    );
    drop(root);
    assert_eq!(
        bytes(&e, &[NativeName::Utf16(n.long_name.clone().unwrap())], &r),
        vec![0x42; 700]
    );
    let root = e.open_directory(&[], &r).unwrap();
    assert_eq!(root.identity().generation, e.generation());
    assert!(
        root.entries()
            .iter()
            .all(|entry| entry.identity().generation == e.generation())
    );
    let dir = name(b"NEW_DIR    ", Some("new directory"));
    e.commit(
        e.plan_create_directory(&root, &dir, &FatCreateMetadata::zeroed(16), &r)
            .unwrap(),
        [9; 16],
        &r,
    )
    .unwrap();
    drop(root);
    let root = e.open_directory(&[], &r).unwrap();
    let dest = e
        .open_directory(&[NativeName::Utf16(dir.long_name.clone().unwrap())], &r)
        .unwrap();
    let moved = name(b"MOVED   BIN", Some("moved.bin"));
    e.commit(
        e.plan_rename(
            &root,
            &NativeName::Utf16(n.long_name.unwrap()),
            &dest,
            &moved,
            &r,
        )
        .unwrap(),
        [10; 16],
        &r,
    )
    .unwrap();
    drop((root, dest));
    assert_eq!(
        bytes(
            &e,
            &[
                NativeName::Utf16(dir.long_name.clone().unwrap()),
                NativeName::Utf16(moved.long_name.clone().unwrap())
            ],
            &r
        ),
        vec![0x42; 700]
    );
    let root = e.open_directory(&[], &r).unwrap();
    assert!(
        e.plan_delete(
            &root,
            &NativeName::Utf16(dir.long_name.clone().unwrap()),
            &r
        )
        .is_err()
    );
    drop(root);
    let d = e
        .open_directory(&[NativeName::Utf16(dir.long_name.clone().unwrap())], &r)
        .unwrap();
    e.commit(
        e.plan_delete(&d, &NativeName::Utf16(moved.long_name.unwrap()), &r)
            .unwrap(),
        [11; 16],
        &r,
    )
    .unwrap();
    drop(d);
    let root = e.open_directory(&[], &r).unwrap();
    e.commit(
        e.plan_delete(&root, &NativeName::Utf16(dir.long_name.unwrap()), &r)
            .unwrap(),
        [12; 16],
        &r,
    )
    .unwrap();
    drop(root);
    assert_eq!(bytes(&e, &[native(b"KEEP    BIN")], &r), b"keep!!!");
    drop(e);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn grow_full_directory_initializes_poisoned_cluster_and_preserves_file_bytes() {
    let r = resources();
    let original = fixture(true);
    let mut e = editor(&original, Arc::new(Mutex::new(Clock::default())), &r);
    let parent = e.open_directory(&[native(b"PARENT     ")], &r).unwrap();
    let n = name(b"CREATED BIN", Some("created long.bin"));
    let b = e
        .plan_create_file(
            &parent,
            &n,
            &FatCreateMetadata::zeroed(32),
            &[0x42; 700],
            &r,
        )
        .unwrap();
    assert_eq!(b.namespace_report().unwrap().parent_growth_clusters, 1);
    e.commit(b, [8; 16], &r).unwrap();
    drop(parent);
    assert_eq!(
        bytes(
            &e,
            &[
                native(b"PARENT     "),
                NativeName::Utf16(n.long_name.unwrap())
            ],
            &r
        ),
        vec![0x42; 700]
    );
    let (target, _, _) = e.into_stores();
    assert_eq!(
        &target.bytes[BASE + 2048..BASE + 2648],
        &original[BASE + 2048..BASE + 2648]
    );
    // First free cluster7 +8 become data;9 extends the parent. Poison must become zero beyond EOF.
    assert!(
        target.bytes[BASE + 5120 + 188..BASE + 5632]
            .iter()
            .all(|b| *b == 0)
    );
    assert!(
        target.bytes[BASE + 5632 + 96..BASE + 6144]
            .iter()
            .all(|b| *b == 0)
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn directory_move_dotdot_descendant_gate_and_corrupt_parent_rejection() {
    let r = resources();
    let mut e = editor(&fixture(false), Arc::new(Mutex::new(Clock::default())), &r);
    let root = e.open_directory(&[], &r).unwrap();
    e.commit(
        e.plan_create_directory(
            &root,
            &name(b"DEST       ", None),
            &FatCreateMetadata::zeroed(16),
            &r,
        )
        .unwrap(),
        [8; 16],
        &r,
    )
    .unwrap();
    drop(root);
    let root = e.open_directory(&[], &r).unwrap();
    let dest = e.open_directory(&[native(b"DEST       ")], &r).unwrap();
    e.commit(
        e.plan_rename(
            &root,
            &native(b"PARENT     "),
            &dest,
            &name(b"MOVEDDIR   ", None),
            &r,
        )
        .unwrap(),
        [9; 16],
        &r,
    )
    .unwrap();
    drop((root, dest));
    assert_eq!(
        bytes(
            &e,
            &[
                native(b"DEST       "),
                native(b"MOVEDDIR   "),
                native(b"NESTED  BIN")
            ],
            &r
        ),
        b"inner"
    );
    let root = e.open_directory(&[], &r).unwrap();
    let descendant = e
        .open_directory(&[native(b"DEST       "), native(b"MOVEDDIR   ")], &r)
        .unwrap();
    assert_eq!(
        e.plan_rename(
            &root,
            &native(b"DEST       "),
            &descendant,
            &name(b"CYCLE      ", None),
            &r
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::InvalidOperation
    );
    drop((root, descendant, e));
    let mut source = fixture(false);
    w(&mut source, BASE + 3584 + 32 + 26, 6);
    let c = Arc::new(Mutex::new(Clock::default()));
    let e = editor(&source, c.clone(), &r);
    assert_eq!(
        e.open_directory(&[native(b"PARENT     ")], &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidData
    );
    let root = e.open_directory(&[], &r).unwrap();
    assert_eq!(
        e.plan_rename(
            &root,
            &native(b"PARENT     "),
            &root,
            &name(b"OTHERDIR   ", None),
            &r
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::InvalidData
    );
    assert_eq!(c.lock().unwrap().events, 0);
    drop((root, e));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn native_name_collisions_context_policy_lfn_boundaries_and_illegal_fields() {
    let r = resources();
    let c = Arc::new(Mutex::new(Clock::default()));
    let mut e = editor(&fixture(false), c, &r);
    let root = e.open_directory(&[], &r).unwrap();
    let collision = name(b"OTHER   BIN", Some("payload.bin"));
    assert_eq!(
        e.plan_create_file(&root, &collision, &FatCreateMetadata::zeroed(32), &[], &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::InvalidOperation
    );
    for n in [
        name(b"bad     BIN", None),
        name(b"BAD.DOT BIN", None),
        name(b"GOOD    BIN", Some("bad.")),
        name(b"GOOD    BIN", Some("bad/name")),
    ] {
        assert!(
            e.plan_create_file(&root, &n, &FatCreateMetadata::zeroed(32), &[], &r)
                .is_err()
        );
    }
    let mut unicode = name(b"UNICODE BIN", Some("resume-\u{00e9}.bin"));
    assert_eq!(
        e.plan_create_file(&root, &unicode, &FatCreateMetadata::zeroed(32), &[], &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Unsupported
    );
    unicode.policy = FatNamePolicy::CallerVerifiedNativeCaseDistinct;
    e.commit(
        e.plan_create_file(&root, &unicode, &FatCreateMetadata::zeroed(32), &[], &r)
            .unwrap(),
        [8; 16],
        &r,
    )
    .unwrap();
    drop(root);
    assert_eq!(
        bytes(&e, &[NativeName::Utf16(unicode.long_name.unwrap())], &r),
        Vec::<u8>::new()
    );
    let root = e.open_directory(&[], &r).unwrap();
    assert_eq!(
        e.plan_create_file(
            &root,
            &name(b"ASCII   BIN", None),
            &FatCreateMetadata::zeroed(32),
            &[],
            &r
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Unsupported
    );
    drop((root, e));
    let mut e = editor(&fixture(false), Arc::new(Mutex::new(Clock::default())), &r);
    for (i, len) in [13, 26, 255].into_iter().enumerate() {
        let parent = e.open_directory(&[native(b"PARENT     ")], &r).unwrap();
        let alias = format!("NEW{i:05}BIN");
        let long = (b'a' + i as u8) as char;
        let n = name(
            alias.as_bytes().try_into().unwrap(),
            Some(&long.to_string().repeat(len)),
        );
        e.commit(
            e.plan_create_file(&parent, &n, &FatCreateMetadata::zeroed(32), &[], &r)
                .unwrap(),
            [10 + i as u8; 16],
            &r,
        )
        .unwrap();
        drop(parent);
        assert_eq!(
            bytes(
                &e,
                &[
                    native(b"PARENT     "),
                    NativeName::Utf16(n.long_name.unwrap())
                ],
                &r
            ),
            Vec::<u8>::new()
        );
    }
    drop(e);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn inplace_vfat_rename_preserves_native_metadata_and_tombstones_old_prefix() {
    let r = resources();
    let mut e = editor(&fixture(false), Arc::new(Mutex::new(Clock::default())), &r);
    let root = e.open_directory(&[], &r).unwrap();
    let old = name(b"OLDNAME BIN", Some("old name longer.bin"));
    let mut meta = FatCreateMetadata::zeroed(32);
    w(&mut meta.raw, 14, 10 << 11 | 20 << 5 | 15);
    w(&mut meta.raw, 22, 11 << 11 | 21 << 5 | 16);
    for at in [16, 18, 24] {
        w(&mut meta.raw, at, 44 << 9 | 10 << 5 | 8);
    }
    meta.raw[13] = 123;
    e.commit(
        e.plan_create_file(&root, &old, &meta, &[0x42; 77], &r)
            .unwrap(),
        [8; 16],
        &r,
    )
    .unwrap();
    drop(root);
    let root = e.open_directory(&[], &r).unwrap();
    let entry = root
        .entries()
        .iter()
        .find(|e| e.name() == &NativeName::Utf16(old.long_name.clone().unwrap()))
        .unwrap();
    let metadata = *entry.raw_metadata();
    let id = entry.identity().native.clone();
    let new = name(b"NEWNAME BIN", Some("new.bin"));
    let b = e
        .plan_rename(
            &root,
            &NativeName::Utf16(old.long_name.unwrap()),
            &root,
            &new,
            &r,
        )
        .unwrap();
    assert_eq!(b.namespace_report().unwrap().allocated_clusters, 0);
    e.commit(b, [9; 16], &r).unwrap();
    drop(root);
    let root = e.open_directory(&[], &r).unwrap();
    let entry = root
        .entries()
        .iter()
        .find(|e| e.name() == &NativeName::Utf16(new.long_name.clone().unwrap()))
        .unwrap();
    assert_eq!(&entry.raw_metadata()[11..], &metadata[11..]);
    assert_eq!(entry.identity().native, id);
    assert_eq!(
        bytes(&e, &[NativeName::Utf16(new.long_name.unwrap())], &r),
        vec![0x42; 77]
    );
    drop((root, e));
    assert_eq!(r.memory.used(), 0);
}
fn fault_fixture() -> Vec<u8> {
    let mut b = fixture(true);
    for (i, cluster) in [(3, 7), (4, 8)] {
        b[BASE + 1536 + i * 32..BASE + 1536 + (i + 1) * 32].copy_from_slice(&short(
            if i == 3 {
                b"DEST       "
            } else {
                b"EMPTY      "
            },
            cluster,
            0,
            16,
        ));
        for copy in 0..2 {
            set_fat(&mut b[BASE..], copy, cluster as usize, 0xfff);
        }
        let at = BASE + 2048 + (cluster as usize - 2) * 512;
        b[at..at + 512].fill(0);
        b[at..at + 32].copy_from_slice(&short(b".          ", cluster, 0, 16));
        b[at + 32..at + 64].copy_from_slice(&short(b"..         ", 0, 0, 16));
        if i == 3 {
            for slot in 2..16 {
                let alias = format!("D{slot:07}BIN");
                b[at + slot * 32..at + (slot + 1) * 32].copy_from_slice(&short(
                    alias.as_bytes().try_into().unwrap(),
                    0,
                    0,
                    32,
                ));
            }
        }
    }
    b
}
fn action<S: Storage, J: Storage>(
    e: &FatEditor<S, J>,
    which: usize,
    r: &Resources,
) -> FatEditBatch {
    let root = e.open_directory(&[], r).unwrap();
    match which {
        0 => {
            let d = e.open_directory(&[native(b"PARENT     ")], r).unwrap();
            e.plan_create_file(
                &d,
                &name(b"CREATED BIN", Some("created long.bin")),
                &FatCreateMetadata::zeroed(32),
                &[0x42; 700],
                r,
            )
            .unwrap()
        }
        1 => e
            .plan_create_file(
                &root,
                &name(b"CREATED BIN", Some("created long.bin")),
                &FatCreateMetadata::zeroed(32),
                &[0x42; 700],
                r,
            )
            .unwrap(),
        2 => {
            let d = e.open_directory(&[native(b"PARENT     ")], r).unwrap();
            e.plan_create_directory(
                &d,
                &name(b"NEW_DIR    ", Some("new directory")),
                &FatCreateMetadata::zeroed(16),
                r,
            )
            .unwrap()
        }
        3 => {
            let d = e.open_directory(&[native(b"PARENT     ")], r).unwrap();
            e.plan_rename(
                &root,
                &native(b"PAYLOAD BIN"),
                &d,
                &name(b"MOVED   BIN", Some("moved long.bin")),
                r,
            )
            .unwrap()
        }
        4 => {
            let d = e.open_directory(&[native(b"DEST       ")], r).unwrap();
            e.plan_rename(
                &root,
                &native(b"PARENT     "),
                &d,
                &name(b"MOVEDDIR   ", Some("moved directory")),
                r,
            )
            .unwrap()
        }
        5 => e.plan_delete(&root, &native(b"PAYLOAD BIN"), r).unwrap(),
        6 => e.plan_delete(&root, &native(b"EMPTY      "), r).unwrap(),
        _ => e
            .plan_rename(
                &root,
                &native(b"PAYLOAD BIN"),
                &root,
                &name(b"CHANGED BIN", None),
                r,
            )
            .unwrap(),
    }
}
#[test]
fn every_namespace_write_barrier_torn_cut_owner_recovery_and_restart_models() {
    let r = resources();
    let seed = fault_fixture();
    for which in 0..8 {
        let c = Arc::new(Mutex::new(Clock::default()));
        let mut e = editor(&seed, c.clone(), &r);
        let b = action(&e, which, &r);
        let mut after = seed.clone();
        for p in b.patches() {
            let at = BASE + p.offset() as usize;
            assert_eq!(&after[at..at + p.expected().len()], p.expected());
            after[at..at + p.replacement().len()].copy_from_slice(p.replacement());
        }
        e.commit(b, [8; 16], &r).unwrap();
        let events = c.lock().unwrap().events;
        drop(e);
        for restart in [None, Some(false), Some(true)] {
            for cut in 1..=events {
                let c = Arc::new(Mutex::new(Clock {
                    events: 0,
                    fail: Some(cut),
                }));
                let mut e = editor(&seed, c.clone(), &r);
                let b = action(&e, which, &r);
                e.commit(b, [8; 16], &r).unwrap_err();
                assert_eq!(e.state(), FatEditState::NeedsRecovery);
                assert!(e.open_directory(&[], &r).is_err());
                c.lock().unwrap().fail = None;
                let (target, state, status) = if let Some(retain) = restart {
                    let (mut target, mut journal, _) = e.into_stores();
                    target.crash(retain);
                    journal.crash(retain);
                    let Ok(status) = fs_undo::inspect(&journal, &r) else {
                        assert_eq!(target.bytes, seed);
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
                        seed.clone()
                    },
                    "operation{which} restart{restart:?} cut{cut}"
                );
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}
#[test]
fn bounds_foreign_scope_readonly_nonempty_metadata_and_no_write_rejection() {
    let r = resources();
    let c = Arc::new(Mutex::new(Clock::default()));
    let e = editor(&fixture(false), c.clone(), &r);
    let root = e.open_directory(&[], &r).unwrap();
    assert!(e.plan_delete(&root, &native(b"PARENT     "), &r).is_err());
    let mut meta = FatCreateMetadata::zeroed(32);
    meta.raw[26] = 1;
    assert!(
        e.plan_create_file(&root, &name(b"CREATED BIN", None), &meta, &[], &r)
            .is_err()
    );
    let other = editor(&fixture(false), Arc::new(Mutex::new(Clock::default())), &r);
    assert_eq!(
        other
            .plan_delete(&root, &native(b"PAYLOAD BIN"), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::StalePlan
    );
    assert_eq!(c.lock().unwrap().events, 0);
    drop((other, root, e));
    for (affected, slots, entries) in [(100, 64, 64), (8192, 4, 64), (8192, 64, 5)] {
        let mut l = limits();
        l.affected_bytes = affected;
        l.audit.directory_slots = slots;
        l.audit.entries = entries;
        let c = Arc::new(Mutex::new(Clock::default()));
        let e = FatEditor::open(
            Model::new(fixture(false), c.clone()),
            Model::new(vec![0; 65536], c.clone()),
            region(),
            binding(),
            l,
            &r,
        )
        .unwrap();
        let root = e.open_directory(&[], &r).unwrap();
        assert_eq!(
            e.plan_create_file(
                &root,
                &name(b"CREATED BIN", Some("created long.bin")),
                &FatCreateMetadata::zeroed(32),
                &[0x42; 700],
                &r
            )
            .err()
            .unwrap()
            .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(c.lock().unwrap().events, 0);
    }
    let mut b = fixture(false);
    b[BASE + 1536 + 11] |= 1;
    let c = Arc::new(Mutex::new(Clock::default()));
    let e = editor(&b, c.clone(), &r);
    let root = e.open_directory(&[], &r).unwrap();
    assert!(e.plan_delete(&root, &native(b"PAYLOAD BIN"), &r).is_err());
    assert!(
        e.plan_rename(
            &root,
            &native(b"PAYLOAD BIN"),
            &root,
            &name(b"OTHER   BIN", None),
            &r
        )
        .is_err()
    );
    assert_eq!(c.lock().unwrap().events, 0);
    r.cancellation.cancel();
    assert_eq!(
        e.plan_delete(&root, &native(b"KEEP    BIN"), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    drop((root, e));
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn max_lfn_crosses_fragmented_directory_growth_preserving_bad_neighbor() {
    let r = resources();
    let mut seed = fixture(false);
    for copy in 0..2 {
        set_fat(&mut seed[BASE..], copy, 8, 0xff7);
    }
    let mut e = editor(&seed, Arc::new(Mutex::new(Clock::default())), &r);
    let parent = e.open_directory(&[native(b"PARENT     ")], &r).unwrap();
    let text = "x".repeat(255);
    let n = name(b"LONGMAX BIN", Some(&text));
    let b = e
        .plan_create_file(&parent, &n, &FatCreateMetadata::zeroed(32), &[], &r)
        .unwrap();
    assert_eq!(b.namespace_report().unwrap().parent_growth_clusters, 2);
    e.commit(b, [8; 16], &r).unwrap();
    drop(parent);
    assert_eq!(
        bytes(
            &e,
            &[
                native(b"PARENT     "),
                NativeName::Utf16(n.long_name.unwrap())
            ],
            &r
        ),
        Vec::<u8>::new()
    );
    let (target, _, _) = e.into_stores();
    assert_eq!(
        &target.bytes[BASE + 5120..BASE + 5632],
        &seed[BASE + 5120..BASE + 5632]
    );
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

fn independently_fill_native_directories(image: &mut [u8], family: u32) {
    // Independent fixture manipulation: fill unused slots with zero-length native short entries.
    // FAT/allocation/FSInfo remain unchanged; mtools/fsck validate the completed fixture.
    let word = |at| u16::from_le_bytes(image[at..at + 2].try_into().unwrap());
    let dword = |at| u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
    let bps = usize::from(word(11));
    let cb = bps * usize::from(image[13]);
    let reserved = usize::from(word(14));
    let fats = usize::from(image[16]);
    let roots = usize::from(word(17));
    let fat_sectors = if family == 32 {
        dword(36) as usize
    } else {
        usize::from(word(22))
    };
    let root_offset = (reserved + fats * fat_sectors) * bps;
    let data_offset = root_offset + (roots * 32).div_ceil(bps) * bps;
    let root_base = if family == 32 {
        data_offset + (dword(44) as usize - 2) * cb
    } else {
        root_offset
    };
    let mut firsts = Vec::new();
    for index in 0..(if family == 32 { cb / 32 } else { roots }) {
        let at = root_base + index * 32;
        let raw: &[u8; 32] = image[at..at + 32].try_into().unwrap();
        if &raw[..11] == b"PARENT     " || &raw[..11] == b"DEST       " {
            firsts.push(
                u32::from(u16::from_le_bytes([raw[26], raw[27]]))
                    | (u32::from(u16::from_le_bytes([raw[20], raw[21]])) << 16),
            );
        }
    }
    assert_eq!(firsts.len(), 2);
    for mut cluster in firsts {
        let mut ended = false;
        let mut index = 0;
        loop {
            assert!(cluster >= 2);
            let at = data_offset + (cluster as usize - 2) * cb;
            for offset in (0..cb).step_by(32) {
                if image[at + offset] == 0 {
                    ended = true;
                }
                if ended || image[at + offset] == 0xe5 {
                    let alias = format!("Q{index:07}BIN");
                    image[at + offset..at + offset + 32].copy_from_slice(&short(
                        alias.as_bytes().try_into().unwrap(),
                        0,
                        0,
                        32,
                    ));
                }
                index += 1;
            }
            let fat = reserved * bps;
            let n = cluster as usize;
            let next = match family {
                12 => {
                    let at = fat + n * 3 / 2;
                    let raw = u16::from_le_bytes([image[at], image[at + 1]]);
                    u32::from(if n & 1 == 0 { raw & 0xfff } else { raw >> 4 })
                }
                16 => u32::from(u16::from_le_bytes(
                    image[fat + n * 2..fat + n * 2 + 2].try_into().unwrap(),
                )),
                32 => {
                    u32::from_le_bytes(image[fat + n * 4..fat + n * 4 + 4].try_into().unwrap())
                        & 0x0fff_ffff
                }
                _ => unreachable!(),
            };
            if next
                >= match family {
                    12 => 0xff8,
                    16 => 0xfff8,
                    _ => 0x0fff_fff8,
                }
            {
                break;
            }
            cluster = next;
        }
    }
}
fn native_provenance(out: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let mut receipt = String::from("source_hash_capture=top-level-gate-start\n");
    for source in [
        "src/fs_fat_edit.rs",
        "src/fs_fat_edit_namespace.rs",
        "src/fs_fat_edit_resize.rs",
        "src/fs_fat.rs",
        "src/fs_fat_audit.rs",
        "src/fs_undo.rs",
        "src/fs_core.rs",
        "src/fs_file.rs",
        "src/storage.rs",
        "tests/fs_fat_edit_namespace.rs",
        "Cargo.lock",
    ] {
        let bytes = std::fs::read(source).unwrap();
        let snapshot = out.join("sources").join(source);
        std::fs::create_dir_all(snapshot.parent().unwrap()).unwrap();
        std::fs::write(&snapshot, &bytes).unwrap();
        std::fs::File::open(&snapshot).unwrap().sync_all().unwrap();
        receipt.push_str(&format!(
            "source={source} sha256={:x} snapshot={}\n",
            Sha256::digest(&bytes),
            snapshot.display()
        ));
    }
    let binary = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    std::fs::write(out.join("gate-binary"), &binary).unwrap();
    receipt.push_str(&format!(
        "test_binary_sha256={:x}\n",
        Sha256::digest(binary)
    ));
    receipt
}
#[test]
#[ignore = "explicit native namespace gate requires PARTMGR_FAT_NAMESPACE_EVIDENCE and mkfs.fat/mcopy/mmd/mdir/fsck.fat"]
fn native_fat12_16_32_namespace_every_io_cut() {
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf, process::Command};
    let out = PathBuf::from(
        std::env::var_os("PARTMGR_FAT_NAMESPACE_EVIDENCE")
            .expect("enabled namespace gate needs evidence destination"),
    );
    assert!(out.is_absolute());
    fs::create_dir(&out).expect("fresh evidence destination required");
    let mut receipt = String::from(
        "profile=owned FAT namespace transactions; injected regular-file IO, not physical power-loss evidence\n",
    );
    receipt.push_str(&native_provenance(&out));
    let mut tools = std::collections::BTreeMap::new();
    for tool in ["mkfs.fat", "mcopy", "mmd", "mdir", "fsck.fat"] {
        let path = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join(tool))
            .find(|p| p.is_file())
            .expect("enabled namespace gate requires every tool");
        receipt.push_str(&format!(
            "tool={tool} path={} sha256={:x}\n",
            path.display(),
            Sha256::digest(fs::read(&path).unwrap())
        ));
        tools.insert(tool, path);
    }
    let run = |receipt: &mut String, tool: &str, args: Vec<String>, success: bool| {
        let result = Command::new(&tools[tool]).args(&args).output().unwrap();
        let i = receipt.matches("command=").count();
        let stdout = format!("command-{i:04}-{tool}.stdout");
        let stderr = format!("command-{i:04}-{tool}.stderr");
        fs::write(out.join(&stdout), &result.stdout).unwrap();
        fs::write(out.join(&stderr), &result.stderr).unwrap();
        receipt.push_str(&format!("command={} {args:?} expected_success={success}\nstatus={} stdout={stdout} sha256={:x} stderr={stderr} sha256={:x}\n",tools[tool].display(),result.status,Sha256::digest(&result.stdout),Sha256::digest(&result.stderr)));
        fs::write(out.join("receipt.txt"), &*receipt).unwrap();
        assert_eq!(
            result.status.success(),
            success,
            "{tool}: {} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    };
    for tool in ["mkfs.fat", "mcopy", "mmd", "mdir", "fsck.fat"] {
        run(
            &mut receipt,
            tool,
            vec![if matches!(tool, "mkfs.fat" | "fsck.fat") {
                "--help".into()
            } else {
                "-V".into()
            }],
            true,
        );
    }
    let payload: Vec<u8> = (0..131089)
        .map(|i| ((i * 37 + i / 19 + 11) % 251) as u8)
        .collect();
    let host = out.join("payload.bin");
    fs::write(&host, &payload).unwrap();
    let keep = out.join("keep.bin");
    fs::write(&keep, b"native keep unchanged").unwrap();
    let nested = out.join("inner.bin");
    fs::write(&nested, b"inner").unwrap();
    let mut l = limits();
    l.audit.clusters = 131072;
    l.audit.entries = 256;
    l.audit.directory_slots = 256;
    l.file_clusters = 1024;
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
            true,
        );
        for (host, name) in [
            (&host, "::PAYLOAD.BIN"),
            (&keep, "::KEEP.BIN"),
            (&host, "::source long.bin"),
        ] {
            run(
                &mut receipt,
                "mcopy",
                vec![
                    "-i".into(),
                    seed.display().to_string(),
                    host.display().to_string(),
                    name.into(),
                ],
                true,
            );
        }
        for dir in ["PARENT", "DEST", "EMPTY"] {
            run(
                &mut receipt,
                "mmd",
                vec!["-i".into(), seed.display().to_string(), format!("::{dir}")],
                true,
            );
        }
        run(
            &mut receipt,
            "mcopy",
            vec![
                "-i".into(),
                seed.display().to_string(),
                nested.display().to_string(),
                "::PARENT/NESTED.BIN".into(),
            ],
            true,
        );
        let original = fs::read(&seed).unwrap();
        let mut filled = original.clone();
        independently_fill_native_directories(&mut filled, family);
        fs::write(&seed, &filled).unwrap();
        receipt.push_str(&format!("fixture_mutation=independent_short_empty_slots fat={family} before_sha256={:x} after_sha256={:x} FAT_and_FSInfo_unchanged=true\n",Sha256::digest(&original),Sha256::digest(&filled)));
        run(
            &mut receipt,
            "fsck.fat",
            vec!["-n".into(), seed.display().to_string()],
            true,
        );
        for dir in ["PARENT", "DEST"] {
            run(
                &mut receipt,
                "mdir",
                vec!["-i".into(), seed.display().to_string(), format!("::{dir}")],
                true,
            );
        }
        let mut before = vec![0xa5; BASE];
        before.extend(filled);
        before.extend([0x5a; 2048]);
        let selected = FatEditRegion {
            offset: BASE as u64,
            length: length as u64,
        };
        for which in 0..9 {
            let case = out.join(format!("fat{family}-operation{which}"));
            fs::create_dir(&case).unwrap();
            let container = case.join("container.img");
            let journal = case.join("journal.bin");
            let oracle = case.join("oracle.img");
            let extracted = case.join("extracted.bin");
            let keep_out = case.join("keep.bin");
            let mut events = 0;
            let mut after = Vec::new();
            let r = resources();
            for cut in 0..256 {
                if cut != 0 && cut > events {
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
                let mut e = FatEditor::open(target, external, selected, binding(), l, &r).unwrap();
                let b = if which == 8 {
                    let root = e.open_directory(&[], &r).unwrap();
                    e.plan_rename(
                        &root,
                        &NativeName::Utf16("source long.bin".encode_utf16().collect()),
                        &root,
                        &name(b"NEWNAME BIN", Some("new.bin")),
                        &r,
                    )
                    .unwrap()
                } else {
                    action(&e, which, &r)
                };
                if matches!(which, 0 | 2 | 3 | 4) {
                    assert_eq!(b.namespace_report().unwrap().parent_growth_clusters, 1);
                }
                if cut == 0 {
                    after = before.clone();
                    for p in b.patches() {
                        let at = BASE + p.offset() as usize;
                        assert_eq!(&before[at..at + p.expected().len()], p.expected());
                        after[at..at + p.replacement().len()].copy_from_slice(p.replacement());
                    }
                    receipt.push_str(&format!("fat={family} operation={which} report={:?} patches={} affected={} before_sha256={:x} after_sha256={:x}\n",b.namespace_report().unwrap(),b.patches().len(),b.affected_bytes(),Sha256::digest(&before),Sha256::digest(&after)));
                }
                let result = e.commit(b, [8; 16], &r);
                let status = if cut == 0 {
                    let status = result.unwrap();
                    events = c.lock().unwrap().events;
                    assert!(events < 256);
                    status
                } else {
                    let error = result.unwrap_err();
                    assert_eq!(e.state(), FatEditState::NeedsRecovery);
                    receipt.push_str(&format!("fat={family} operation={which} cut={cut} failure_stage={} target_may_have_changed={}\n",error.stage,error.target_may_have_changed));
                    c.lock().unwrap().fail = None;
                    e.recover(&r).unwrap()
                };
                let committed = status.state == UndoState::Committed;
                let (target, external, state) = e.into_stores();
                assert_eq!(state, FatEditState::Ready);
                drop((target, external));
                assert_eq!(r.memory.used(), 0);
                let actual = fs::read(&container).unwrap();
                assert_eq!(
                    actual,
                    if committed {
                        after.clone()
                    } else {
                        before.clone()
                    },
                    "fat{family} operation{which} cut{cut}: outside approved patches changed"
                );
                fs::write(&oracle, &actual[BASE..BASE + length]).unwrap();
                run(
                    &mut receipt,
                    "fsck.fat",
                    vec!["-n".into(), oracle.display().to_string()],
                    true,
                );
                assert_eq!(fs::read(&oracle).unwrap(), actual[BASE..BASE + length]);
                if keep_out.exists() {
                    fs::remove_file(&keep_out).unwrap();
                }
                run(
                    &mut receipt,
                    "mcopy",
                    vec![
                        "-i".into(),
                        format!("{}@@{BASE}", container.display()),
                        "::KEEP.BIN".into(),
                        keep_out.display().to_string(),
                    ],
                    true,
                );
                assert_eq!(fs::read(&keep_out).unwrap(), b"native keep unchanged");
                let (new_path, old_path, expected) = match which {
                    0 => ("::PARENT/created long.bin", "", vec![0x42; 700]),
                    1 => ("::created long.bin", "", vec![0x42; 700]),
                    2 => ("::PARENT/new directory", "", Vec::new()),
                    3 => ("::PARENT/moved long.bin", "::PAYLOAD.BIN", payload.clone()),
                    4 => (
                        "::DEST/moved directory/NESTED.BIN",
                        "::PARENT/NESTED.BIN",
                        b"inner".to_vec(),
                    ),
                    5 => ("", "::PAYLOAD.BIN", payload.clone()),
                    6 => ("", "::EMPTY", Vec::new()),
                    7 => ("::CHANGED.BIN", "::PAYLOAD.BIN", payload.clone()),
                    _ => ("::new.bin", "::source long.bin", payload.clone()),
                };
                let path = if committed || old_path.is_empty() {
                    new_path
                } else {
                    old_path
                };
                let present =
                    !(committed && new_path.is_empty() || !committed && old_path.is_empty());
                if matches!(which, 2 | 6) || !present {
                    let pattern = if path.is_empty() { old_path } else { path };
                    run(
                        &mut receipt,
                        "mdir",
                        vec![
                            "-i".into(),
                            format!("{}@@{BASE}", container.display()),
                            pattern.into(),
                        ],
                        present,
                    );
                } else {
                    if extracted.exists() {
                        fs::remove_file(&extracted).unwrap();
                    }
                    run(
                        &mut receipt,
                        "mcopy",
                        vec![
                            "-i".into(),
                            format!("{}@@{BASE}", container.display()),
                            path.into(),
                            extracted.display().to_string(),
                        ],
                        true,
                    );
                    assert_eq!(fs::read(&extracted).unwrap(), expected);
                }
                assert_eq!(fs::read(&container).unwrap(), actual);
                receipt.push_str(&format!("fat={family} operation={which} cut={cut} result={:?} target_sha256={:x} journal_sha256={:x} expected_payload_sha256={:x} outside_patch_bytes_exact=true\n",status.state,Sha256::digest(&actual),Sha256::digest(fs::read(&journal).unwrap()),Sha256::digest(&expected)));
                fs::write(out.join("receipt.txt"), &receipt).unwrap();
                if cut == 0 {
                    fs::copy(&container, case.join("committed-container.img")).unwrap();
                }
            }
            eprintln!(
                "native namespace FAT{family} operation{which}: normal + all{events} write/barrier cuts passed"
            );
        }
    }
    receipt.push_str("result=passed\n");
    fs::write(out.join("receipt.txt"), receipt).unwrap();
    fn sync(path: &std::path::Path) {
        if path.is_dir() {
            for child in std::fs::read_dir(path).unwrap() {
                sync(&child.unwrap().path());
            }
        }
        std::fs::File::open(path).unwrap().sync_all().unwrap();
    }
    sync(&out);
    eprintln!(
        "native namespace receipt {}",
        out.join("receipt.txt").display()
    );
}
