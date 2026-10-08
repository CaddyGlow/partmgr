use partmgr::{
    fs_core::*, fs_flash::*, fs_jffs2::*, fs_jffs2_audit::*, fs_jffs2_edit::*, storage::Storage,
};
use std::{
    io,
    sync::{Arc, Mutex},
};
#[allow(dead_code)]
#[path = "fixtures/jffs2_clean.rs"]
mod fixture;
#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    durable: Vec<u8>,
    writes: usize,
    flushes: usize,
    reads: usize,
    fail_write: Option<usize>,
    fail_flush: Option<usize>,
    fail_read: bool,
}
struct Backend(Arc<Mutex<State>>);
impl Storage for Backend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().bytes.len() as u64)
    }
    fn read_exact_at(&self, p: u64, out: &mut [u8]) -> io::Result<()> {
        let mut s = self.0.lock().unwrap();
        s.reads += 1;
        if s.fail_read {
            return Err(io::Error::other("causal modeled read failure"));
        }
        out.copy_from_slice(
            s.bytes
                .get(p as usize..p as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, p: u64, b: &[u8]) -> io::Result<usize> {
        let mut s = self.0.lock().unwrap();
        s.writes += 1;
        let n = if s.fail_write == Some(s.writes) {
            b.len().min(4)
        } else {
            b.len()
        };
        s.bytes[p as usize..p as usize + n].copy_from_slice(&b[..n]);
        if s.fail_write == Some(s.writes) {
            return Err(io::Error::other("causal hidden partial write"));
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut s = self.0.lock().unwrap();
        s.flushes += 1;
        if s.fail_flush == Some(s.flushes) {
            Err(io::Error::other("causal modeled flush failure"))
        } else {
            s.durable = s.bytes.clone();
            Ok(())
        }
    }
}
fn state(bytes: Vec<u8>) -> Arc<Mutex<State>> {
    Arc::new(Mutex::new(State {
        durable: bytes.clone(),
        bytes,
        ..State::default()
    }))
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    }
}
fn geometry() -> FlashGeometry {
    FlashGeometry {
        erased_byte: 255,
        programming: FlashProgramming::ClearBitsOnly,
        erase_bytes: 4096,
        program_bytes: 4,
        layout: FlashLayout::LogicalNor,
    }
}
fn limits() -> Jffs2EditLimits {
    Jffs2EditLimits {
        read: Jffs2ReadLimits {
            scan_bytes: 1 << 20,
            nodes: 128,
            inodes: 32,
            fragments: 128,
            native_bytes: 4096,
            work: 100_000,
        },
        audit: Jffs2AuditLimits {
            entries: 128,
            work: 128,
            findings: 16,
        },
        journal_bytes: 32768,
        slots: 32,
        file_bytes: 2048,
        scratch_bytes: 128,
    }
}
fn flash(s: &Arc<Mutex<State>>, r: &Resources) -> FlashImage<Backend> {
    FlashImage::new(
        Backend(s.clone()),
        geometry(),
        &[],
        FlashLimits {
            bad_blocks: 0,
            operation_bytes: 8192,
            scratch_bytes: 128,
        },
        r,
    )
    .unwrap()
}
fn d(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
fn finish(mut b: Vec<u8>, kind: u16) -> Vec<u8> {
    b[..2].copy_from_slice(&0x1985u16.to_le_bytes());
    b[2..4].copy_from_slice(&kind.to_le_bytes());
    let n = b.len() as u32;
    d(&mut b, 4, n);
    let c = fixture::crc(&b[..8]);
    d(&mut b, 8, c);
    if kind != 0x2003 {
        let c = fixture::crc(&b[..if kind == 0xe002 { 60 } else { 32 }]);
        d(&mut b, if kind == 0xe002 { 64 } else { 32 }, c);
    }
    b.resize((b.len() + 3) & !3, 255);
    b
}
fn node(n: u32, kind: u32, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 68 + payload.len()];
    d(&mut b, 12, n);
    d(&mut b, 16, 1);
    d(&mut b, 20, kind | 0o640);
    b[24..26].copy_from_slice(&123u16.to_le_bytes());
    b[26..28].copy_from_slice(&456u16.to_le_bytes());
    d(&mut b, 28, payload.len() as u32);
    for p in [32, 36, 40] {
        d(&mut b, p, 23);
    }
    d(&mut b, 48, payload.len() as u32);
    d(&mut b, 52, payload.len() as u32);
    b[68..].copy_from_slice(payload);
    d(&mut b, 60, fixture::crc(payload));
    finish(b, 0xe002)
}
fn entry(n: u32, v: u32, kind: u8, name: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 40 + name.len()];
    d(&mut b, 12, 1);
    d(&mut b, 16, v);
    d(&mut b, 20, n);
    d(&mut b, 24, 23);
    b[28] = name.len() as u8;
    b[29] = kind;
    b[40..].copy_from_slice(name);
    d(&mut b, 36, fixture::crc(name));
    finish(b, 0xe001)
}
fn seed() -> Vec<u8> {
    let mut image = vec![255; 6 * 4096];
    let clean = finish(vec![0; 12], 0x2003);
    for p in (0..image.len()).step_by(4096) {
        image[p..p + 12].copy_from_slice(&clean);
    }
    let mut p = 12;
    for b in [
        node(1, 0x4000, b""),
        node(2, 0x8000, b"original"),
        node(3, 0x8000, b"unrelated"),
        node(4, 0x8000, b"shared"),
        entry(2, 1, 8, b"payload"),
        entry(3, 2, 8, b"other"),
        entry(4, 3, 8, b"alias-a"),
        entry(4, 4, 8, b"alias-b"),
        entry(0, 7, 8, b"deleted"),
    ] {
        image[p..p + b.len()].copy_from_slice(&b);
        p += b.len();
    }
    p = 3 * 4096 + 12;
    for b in [
        node(100, 0x8000, b"deleted history"),
        entry(100, 6, 8, b"deleted"),
    ] {
        image[p..p + b.len()].copy_from_slice(&b);
        p += b.len();
    }
    p = 4 * 4096 + 12;
    for b in [node(5, 0xa000, b"payload"), entry(5, 5, 10, b"link")] {
        image[p..p + b.len()].copy_from_slice(&b);
        p += b.len();
    }
    image
}
struct Immutable(Vec<u8>);
impl virtdisk::ReadAt for Immutable {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, p: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(
            self.0
                .get(p as usize..p as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn assert_payload(bytes: &[u8], expected: &[u8], r: &Resources) {
    let v = Jffs2Volume::open(
        Arc::new(Immutable(bytes.to_vec())),
        geometry(),
        Jffs2Endian::Little,
        limits().read,
        r,
    )
    .unwrap();
    assert!(audit(&v, limits().audit, r).unwrap().is_clean());
    let root = v.inode(1).unwrap();
    assert!(root.deleted_entries().iter().any(|e| e.name == b"deleted"));
    let tree = partmgr::fs_jffs2_tree::Jffs2TreeSource::inventory(v, limits().audit, r).unwrap();
    let root = tree.root();
    let page = tree.directory_page(&root, None, 64, r).unwrap();
    let p = page
        .entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"payload".to_vec()))
        .unwrap();
    let file = tree.open_stream(&p.object, &StreamKind::Data, r).unwrap();
    assert_eq!(
        read_all(file.as_ref(), 2048, r).unwrap().get().as_slice(),
        expected
    );
}
#[test]
fn successful_append_and_gc_preserve_names_hardlinks_tombstones_and_outside_ranges() {
    let r = resources();
    let original = seed();
    let s = state(original.clone());
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let root = editor.identity(1).unwrap();
    assert_eq!(root.source >> 64, 13);
    let plan = editor
        .replace(&root, b"payload", b"replacement", 31, &r)
        .unwrap();
    let j = state(vec![0; plan.journal_length() as usize]);
    let report = editor.commit(plan, &mut Backend(j.clone()), &r).unwrap();
    assert!(!report.mutation_uncertain);
    assert_payload(&s.lock().unwrap().bytes, b"replacement", &r);
    assert_eq!(&s.lock().unwrap().bytes[3 * 4096..], &original[3 * 4096..]);
    let plan = editor.collect(0, &r).unwrap();
    let j2 = state(vec![0; plan.journal_length() as usize]);
    let report = editor.commit(plan, &mut Backend(j2), &r).unwrap();
    assert!(report.garbage_collection);
    assert!(s.lock().unwrap().bytes[..4096].iter().all(|b| *b == 255));
    assert_payload(&s.lock().unwrap().bytes, b"replacement", &r);
    assert_eq!(&s.lock().unwrap().bytes[3 * 4096..], &original[3 * 4096..]);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}
#[derive(Clone, Copy, Debug)]
enum Cut {
    TargetWrite(usize),
    TargetFlush(usize),
    JournalWrite(usize),
    JournalFlush(usize),
    None,
}
fn crash(state: &Arc<Mutex<State>>, retain: bool) {
    let mut s = state.lock().unwrap();
    if !retain {
        s.bytes = s.durable.clone();
    }
    s.durable = s.bytes.clone();
    s.fail_write = None;
    s.fail_flush = None;
    s.writes = 0;
    s.flushes = 0;
}
fn trial(gc: bool, cut: Cut, persist: (bool, bool)) -> (usize, usize, usize, usize) {
    trial_for(gc, 0, cut, persist)
}
fn trial_for(
    gc: bool,
    victim: u64,
    cut: Cut,
    persist: (bool, bool),
) -> (usize, usize, usize, usize) {
    let r = resources();
    let original = seed();
    let s = state(original.clone());
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let plan = if gc {
        editor.collect(victim, &r).unwrap()
    } else {
        editor
            .replace(
                &editor.identity(1).unwrap(),
                b"payload",
                b"complete replacement",
                31,
                &r,
            )
            .unwrap()
    };
    let expected = plan.expected_sha256();
    let j = state(vec![0; plan.journal_length() as usize]);
    match cut {
        Cut::TargetWrite(n) => s.lock().unwrap().fail_write = Some(n),
        Cut::TargetFlush(n) => s.lock().unwrap().fail_flush = Some(n),
        Cut::JournalWrite(n) => j.lock().unwrap().fail_write = Some(n),
        Cut::JournalFlush(n) => j.lock().unwrap().fail_flush = Some(n),
        Cut::None => {}
    }
    let result = editor.commit(plan, &mut Backend(j.clone()), &r);
    let counts = {
        let s = s.lock().unwrap();
        let j = j.lock().unwrap();
        (s.writes, s.flushes, j.writes, j.flushes)
    };
    if matches!(cut, Cut::None) {
        assert!(result.is_ok(), "{result:?}");
        drop(editor);
        assert_eq!(r.memory.used(), 0);
        return counts;
    }
    let failure = result.unwrap_err();
    assert!(failure.source.source.is_some(), "{cut:?}: {failure:?}");
    let source_before = s.lock().unwrap().bytes.clone();
    let writes_before = s.lock().unwrap().writes;
    drop(editor.into_flash());
    crash(&s, persist.0);
    crash(&j, persist.1);
    {
        let mut s = s.lock().unwrap();
        s.fail_write = None;
        s.fail_flush = None;
        s.writes = 0;
        s.flushes = 0;
    }
    {
        let mut j = j.lock().unwrap();
        j.fail_write = None;
        j.fail_flush = None;
    }
    let mut reopened = flash(&s, &r);
    let recovered = recover(
        &mut reopened,
        &mut Backend(j.clone()),
        [7; 32],
        Jffs2Endian::Little,
        limits(),
        &r,
    );
    match recovered {
        Ok(report) => {
            assert_eq!(report.sha256, expected, "{cut:?}");
            assert_payload(
                &s.lock().unwrap().bytes,
                if gc {
                    b"original"
                } else {
                    b"complete replacement"
                },
                &r,
            );
            let count = s.lock().unwrap().writes;
            let repeated = recover(
                &mut reopened,
                &mut Backend(j),
                [7; 32],
                Jffs2Endian::Little,
                limits(),
                &r,
            )
            .unwrap();
            assert_eq!(repeated.sha256, expected);
            assert_eq!(
                s.lock().unwrap().writes,
                count,
                "complete recovery must be idempotent"
            );
        }
        Err(e) => {
            assert_eq!(
                writes_before, 0,
                "{cut:?} lost valid intent after mutation: {e:?}"
            );
            assert_eq!(source_before, original);
            assert_eq!(s.lock().unwrap().writes, 0);
        }
    }
    if gc && victim == 0 {
        assert_eq!(&s.lock().unwrap().bytes[2 * 4096..], &original[2 * 4096..]);
    } else if gc {
        assert_eq!(&s.lock().unwrap().bytes[..4096], &original[..4096]);
        assert_eq!(
            &s.lock().unwrap().bytes[2 * 4096..4 * 4096],
            &original[2 * 4096..4 * 4096]
        );
        assert_eq!(&s.lock().unwrap().bytes[5 * 4096..], &original[5 * 4096..]);
    } else {
        assert_eq!(&s.lock().unwrap().bytes[..4096], &original[..4096]);
        assert_eq!(&s.lock().unwrap().bytes[2 * 4096..], &original[2 * 4096..]);
    }
    drop(reopened);
    assert_eq!(r.memory.used(), 0);
    counts
}
#[test]
fn every_append_and_gc_program_erase_journal_and_flush_cut_recovers_or_never_touched_target() {
    for gc in [false, true] {
        let (tw, tf, jw, jf) = trial(gc, Cut::None, (true, true));
        assert!(tw > 0 && tf > 0 && jw >= 3 && jf >= 3);
        for persist in [(false, false), (false, true), (true, false), (true, true)] {
            for n in 1..=tw {
                trial(gc, Cut::TargetWrite(n), persist);
            }
            for n in 1..=tf {
                trial(gc, Cut::TargetFlush(n), persist);
            }
            for n in 1..=jw {
                trial(gc, Cut::JournalWrite(n), persist);
            }
            for n in 1..=jf {
                trial(gc, Cut::JournalFlush(n), persist);
            }
        }
    }
}
#[test]
fn binding_tamper_incompatible_bits_and_prepared_victim_change_never_replay() {
    for gc in [false, true] {
        let r = resources();
        let s = state(seed());
        let mut editor =
            Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
        let plan = if gc {
            editor.collect(0, &r).unwrap()
        } else {
            editor
                .replace(&editor.identity(1).unwrap(), b"payload", b"new", 31, &r)
                .unwrap()
        };
        let j = state(vec![0; plan.journal_length() as usize]);
        s.lock().unwrap().fail_write = Some(1);
        editor
            .commit(plan, &mut Backend(j.clone()), &r)
            .unwrap_err();
        drop(editor.into_flash());
        s.lock().unwrap().fail_write = None;
        let mut f = flash(&s, &r);
        let count = s.lock().unwrap().writes;
        assert!(
            recover(
                &mut f,
                &mut Backend(j.clone()),
                [8; 32],
                Jffs2Endian::Little,
                limits(),
                &r
            )
            .is_err()
        );
        assert_eq!(s.lock().unwrap().writes, count);
        if gc {
            s.lock().unwrap().bytes[0] = 0;
        } else {
            s.lock().unwrap().bytes[4096 + 12 + 68] = 0;
        }
        assert!(
            recover(
                &mut f,
                &mut Backend(j.clone()),
                [7; 32],
                Jffs2Endian::Little,
                limits(),
                &r
            )
            .is_err()
        );
        assert_eq!(s.lock().unwrap().writes, count);
        drop(f);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn preflight_caps_cancellation_hardlinks_causal_reads_and_sticky_uncertainty() {
    let r = resources();
    let s = state(seed());
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let root = editor.identity(1).unwrap();
    let low = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        editor
            .replace(&root, b"payload", b"x", 2, &low)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(low.memory.used(), 0);
    assert_eq!(s.lock().unwrap().writes, 0);
    assert!(editor.replace(&root, b"alias-a", b"x", 2, &r).is_err());
    assert!(
        editor
            .replace(&root, b"payload", &vec![0; 2049], 2, &r)
            .is_err()
    );
    assert!(editor.collect(4 * 4096, &r).is_ok());
    let plan = editor.replace(&root, b"payload", b"new", 31, &r).unwrap();
    let j = state(vec![0; plan.journal_length() as usize]);
    s.lock().unwrap().fail_write = Some(1);
    let e = editor
        .commit(plan, &mut Backend(j.clone()), &r)
        .unwrap_err();
    assert!(e.mutation_uncertain && e.mutation_attempted);
    assert!(
        Jffs2Volume::open(
            Arc::new(Immutable(s.lock().unwrap().bytes.clone())),
            geometry(),
            Jffs2Endian::Little,
            limits().read,
            &r
        )
        .is_err()
    );
    assert!(editor.replace(&root, b"payload", b"x", 2, &r).is_err());
    let mut f = editor.into_flash();
    s.lock().unwrap().fail_write = None;
    let report = recover(
        &mut f,
        &mut Backend(j),
        [7; 32],
        Jffs2Endian::Little,
        limits(),
        &r,
    )
    .unwrap();
    assert!(report.mutation_uncertain);
    assert!(Jffs2Editor::open(f, [7; 32], Jffs2Endian::Little, limits(), &r).is_err());
    assert_eq!(r.memory.used(), 0);
    let r = resources();
    let s = state(seed());
    let editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    s.lock().unwrap().fail_read = true;
    let e = editor
        .replace(&editor.identity(1).unwrap(), b"payload", b"x", 2, &r)
        .err()
        .unwrap();
    assert!(e.source.is_some());
    assert_eq!(s.lock().unwrap().writes, 0);
    s.lock().unwrap().fail_read = false;
    r.cancellation.cancel();
    let fresh = resources();
    assert!(
        editor
            .replace(&editor.identity(1).unwrap(), b"payload", b"x", 2, &fresh)
            .is_err()
    );
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn historical_only_gc_keeps_inode_floor_and_cannot_resurrect_deleted_name() {
    let r = resources();
    let s = state(seed());
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let plan = editor.collect(3 * 4096, &r).unwrap();
    let j = state(vec![0; plan.journal_length() as usize]);
    editor.commit(plan, &mut Backend(j), &r).unwrap();
    assert!(
        s.lock().unwrap().bytes[3 * 4096..4 * 4096]
            .iter()
            .all(|v| *v == 255)
    );
    let plan = editor
        .replace(&editor.identity(1).unwrap(), b"payload", b"floor", 31, &r)
        .unwrap();
    let j = state(vec![0; plan.journal_length() as usize]);
    editor.commit(plan, &mut Backend(j), &r).unwrap();
    assert!(editor.identity(101).is_ok());
    assert_payload(&s.lock().unwrap().bytes, b"floor", &r);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}
fn q(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}
fn hash(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}
fn refresh_intent(j: &mut [u8], baseline: &[u8]) {
    let n = q(j, 24) as usize;
    let count = u32::from_le_bytes(j[180..184].try_into().unwrap()) as usize;
    let mut copied = baseline.to_vec();
    let mut at = 1024;
    for _ in 0..count {
        let p = q(j, at) as usize;
        let len = q(j, at + 8) as usize;
        at += 16;
        copied[p..p + len].copy_from_slice(&j[at..at + len]);
        at += len;
    }
    let copied_sha = hash(&copied);
    j[200..232].copy_from_slice(&copied_sha);
    let mut after = copied;
    if u32::from_le_bytes(j[20..24].try_into().unwrap()) == 2 {
        let p = q(j, 184) as usize;
        let n = q(j, 192) as usize;
        after[p..p + n].fill(255);
    }
    j[128..160].copy_from_slice(&hash(&after));
    let body_sha = hash(&j[1024..1024 + n]);
    j[32..64].copy_from_slice(&body_sha);
    let h = hash(&j[..480]);
    j[480..512].copy_from_slice(&h);
}
fn prepared(gc: bool) -> (Arc<Mutex<State>>, Arc<Mutex<State>>, Resources) {
    prepared_for(gc, 0)
}
fn prepared_for(gc: bool, victim: u64) -> (Arc<Mutex<State>>, Arc<Mutex<State>>, Resources) {
    let r = resources();
    let s = state(seed());
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let plan = if gc {
        editor.collect(victim, &r).unwrap()
    } else {
        editor
            .replace(&editor.identity(1).unwrap(), b"payload", b"new", 31, &r)
            .unwrap()
    };
    let j = state(vec![0; plan.journal_length() as usize]);
    s.lock().unwrap().fail_write = Some(1);
    editor
        .commit(plan, &mut Backend(j.clone()), &r)
        .unwrap_err();
    drop(editor.into_flash());
    {
        let mut s = s.lock().unwrap();
        s.fail_write = None;
        s.writes = 0;
        s.flushes = 0;
    }
    {
        let mut j = j.lock().unwrap();
        j.writes = 0;
        j.flushes = 0;
    }
    (s, j, r)
}
#[test]
fn recomputed_intent_hashes_never_authorize_invalid_semantics_or_geometry() {
    for case in 0..9 {
        let gc = case == 3;
        let (s, j, r) = prepared(gc);
        let original = seed();
        {
            let mut j = j.lock().unwrap();
            let b = &mut j.bytes;
            let first = 1040;
            let first_len = q(b, 1032) as usize;
            let second = first + first_len;
            match case {
                0 => d(b, 16, 2), // COPIED in sequence one is impossible.
                1 => b[8..16].copy_from_slice(&3u64.to_le_bytes()),
                2 => {
                    let p = q(b, 1024);
                    b[second..second + 8].copy_from_slice(&(p + 4).to_le_bytes());
                }
                3 => b[184..192].copy_from_slice(&4096u64.to_le_bytes()),
                4 => d(b, 232, 0),
                5 => {
                    b[first + 2..first + 4].copy_from_slice(&0xe001u16.to_le_bytes());
                    let c = fixture::crc(&b[first..first + 8]);
                    d(b, first + 8, c);
                }
                6 => {
                    d(b, first + 28, 4);
                    let c = fixture::crc(&b[first..first + 60]);
                    d(b, first + 64, c);
                }
                7 => {
                    let second_node = second + 16;
                    b[second_node + 2..second_node + 4].copy_from_slice(&0x2004u16.to_le_bytes());
                    let c = fixture::crc(&b[second_node..second_node + 8]);
                    d(b, second_node + 8, c);
                }
                8 => {
                    let at = second + 16;
                    b[at + 40..at + 47].copy_from_slice(b"payloaf");
                    let c = fixture::crc(&b[at + 40..at + 47]);
                    d(b, at + 36, c);
                    let c = fixture::crc(&b[at..at + 32]);
                    d(b, at + 32, c);
                }
                _ => unreachable!(),
            }
            refresh_intent(b, &original);
        }
        let source_before = s.lock().unwrap().bytes.clone();
        let journal_before = j.lock().unwrap().bytes.clone();
        let mut f = flash(&s, &r);
        assert!(
            recover(
                &mut f,
                &mut Backend(j.clone()),
                [7; 32],
                Jffs2Endian::Little,
                limits(),
                &r
            )
            .is_err(),
            "case {case}"
        );
        assert_eq!(s.lock().unwrap().writes, 0, "target case {case}");
        assert_eq!(j.lock().unwrap().writes, 0, "journal case {case}");
        assert_eq!(s.lock().unwrap().bytes, source_before);
        assert_eq!(j.lock().unwrap().bytes, journal_before);
        drop(f);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn outside_change_and_complete_digest_mismatch_reject_without_any_writes() {
    let (s, j, r) = prepared(false);
    s.lock().unwrap().bytes[6 * 4096 - 1] = 0;
    let mut f = flash(&s, &r);
    assert!(
        recover(
            &mut f,
            &mut Backend(j.clone()),
            [7; 32],
            Jffs2Endian::Little,
            limits(),
            &r
        )
        .is_err()
    );
    assert_eq!(s.lock().unwrap().writes, 0);
    assert_eq!(j.lock().unwrap().writes, 0);
    drop(f);
    let r = resources();
    let s = state(seed());
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let plan = editor
        .replace(&editor.identity(1).unwrap(), b"payload", b"new", 31, &r)
        .unwrap();
    let j = state(vec![0; plan.journal_length() as usize]);
    editor.commit(plan, &mut Backend(j.clone()), &r).unwrap();
    drop(editor.into_flash());
    s.lock().unwrap().writes = 0;
    j.lock().unwrap().writes = 0;
    s.lock().unwrap().bytes[6 * 4096 - 1] = 0;
    let mut f = flash(&s, &r);
    assert!(
        recover(
            &mut f,
            &mut Backend(j.clone()),
            [7; 32],
            Jffs2Endian::Little,
            limits(),
            &r
        )
        .is_err()
    );
    assert_eq!(s.lock().unwrap().writes, 0);
    assert_eq!(j.lock().unwrap().writes, 0);
    drop(f);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn authenticated_compressed_intent_never_widens_strict_recovery_or_writes() {
    use sha2::{Digest, Sha256};
    let (s, j, r) = prepared(false);
    {
        let mut journal = j.lock().unwrap();
        let header = &mut journal.bytes[..512];
        header[..8].copy_from_slice(b"JFF2TX02");
        for (offset, value) in [(236, 2u32), (240, 4096), (244, 4096)] {
            header[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for offset in [248, 256, 264] {
            header[offset..offset + 8].copy_from_slice(&65536u64.to_le_bytes());
        }
        let hash = Sha256::digest(&header[..480]);
        header[480..].copy_from_slice(&hash);
    }
    let before = s.lock().unwrap().bytes.clone();
    let journal_before = j.lock().unwrap().bytes.clone();
    let mut f = flash(&s, &r);
    let error = recover(
        &mut f,
        &mut Backend(j.clone()),
        [7; 32],
        Jffs2Endian::Little,
        limits(),
        &r,
    )
    .unwrap_err();
    assert_eq!(error.source.kind, ErrorKind::Unsupported);
    assert_eq!(s.lock().unwrap().writes, 0);
    assert_eq!(j.lock().unwrap().writes, 0);
    assert_eq!(s.lock().unwrap().bytes, before);
    assert_eq!(j.lock().unwrap().bytes, journal_before);
    drop(f);
    assert_eq!(r.memory.used(), 0);
}

fn edit_compression(
    codec: partmgr::fs_jffs2_builder::Jffs2BuildCompression,
) -> Jffs2EditCompression {
    Jffs2EditCompression {
        codec,
        read: Jffs2CompressionLimits {
            compressed_node_bytes: 4096,
            decoded_node_bytes: 4096,
            compressed_bytes: 1 << 20,
            decoded_bytes: 1 << 20,
            work: 4 << 20,
        },
    }
}

#[test]
fn compressed_owned_range_truncate_create_replace_and_gc_both_endians_keep_native_hardlinks() {
    use partmgr::fs_jffs2_builder::Jffs2BuildCompression;
    for big in [false, true] {
        for codec in [Jffs2BuildCompression::Rtime, Jffs2BuildCompression::Zlib] {
            let r = resources();
            let endian = if big {
                Jffs2Endian::Big
            } else {
                Jffs2Endian::Little
            };
            let mut initial = seed();
            initial.resize(12 * 4096, 255);
            let source = state(if big { convert_big(initial) } else { initial });
            let profile = edit_compression(codec);
            let mut editor = Jffs2Editor::open_compressed(
                flash(&source, &r),
                [7; 32],
                endian,
                limits(),
                profile,
                &r,
            )
            .unwrap();
            let payload = RangePayload::new(vec![b'A'; 2048]);
            let plan = editor
                .write_range(&editor.identity(4).unwrap(), 2, &payload, 2050, 42, &r)
                .unwrap();
            let journal = state(vec![0; plan.journal_length() as usize]);
            editor
                .commit(plan, &mut Backend(journal.clone()), &r)
                .unwrap();
            assert_eq!(&journal.lock().unwrap().bytes[..8], b"JFF2TX02");
            let plan = editor
                .truncate(&editor.identity(4).unwrap(), 1500, 43, &r)
                .unwrap();
            let journal = state(vec![0; plan.journal_length() as usize]);
            editor.commit(plan, &mut Backend(journal), &r).unwrap();
            let plan = editor
                .replace(
                    &editor.identity(1).unwrap(),
                    if big { b"\xffayload" } else { b"payload" },
                    &[b'B'; 1024],
                    44,
                    &r,
                )
                .unwrap();
            let journal = state(vec![0; plan.journal_length() as usize]);
            editor.commit(plan, &mut Backend(journal), &r).unwrap();
            let metadata = Jffs2CreateMetadata {
                permissions: 0o640,
                uid: 123,
                gid: 456,
                accessed: 11,
                modified: 45,
                changed: 46,
            };
            let plan = editor
                .create_file(
                    &editor.identity(1).unwrap(),
                    b"created-\xff",
                    &[b'C'; 1024],
                    metadata,
                    &r,
                )
                .unwrap();
            let journal = state(vec![0; plan.journal_length() as usize]);
            editor.commit(plan, &mut Backend(journal), &r).unwrap();
            let plan = editor.collect(0, &r).unwrap();
            let journal = state(vec![0; plan.journal_length() as usize]);
            editor.commit(plan, &mut Backend(journal), &r).unwrap();
            drop(editor.into_flash());
            let bytes = source.lock().unwrap().bytes.clone();
            assert!(
                Jffs2Volume::open(
                    Arc::new(Immutable(bytes.clone())),
                    geometry(),
                    endian,
                    limits().read,
                    &r
                )
                .is_err()
            );
            let volume = Jffs2Volume::open_compressed(
                Arc::new(Immutable(bytes)),
                geometry(),
                endian,
                limits().read,
                profile.read,
                &r,
            )
            .unwrap();
            assert!(audit(&volume, limits().audit, &r).unwrap().is_clean());
            let created = volume.open_file(102, &r).unwrap();
            assert_eq!(
                read_all(&created, 2048, &r).unwrap().get().as_slice(),
                &[b'C'; 1024]
            );
            drop(created);
            let file = volume.open_file(4, &r).unwrap();
            let mut expected = b"sh".to_vec();
            expected.resize(1500, b'A');
            assert_eq!(
                read_all(&file, 4096, &r).unwrap().get().as_slice(),
                expected
            );
            drop(file);
            let tree =
                partmgr::fs_jffs2_tree::Jffs2TreeSource::inventory(volume, limits().audit, &r)
                    .unwrap();
            let page = tree.directory_page(&tree.root(), None, 64, &r).unwrap();
            for name in [b"alias-a".as_slice(), b"alias-b"] {
                assert_eq!(
                    page.entries
                        .iter()
                        .find(|e| e.name == NativeName::Bytes(name.to_vec()))
                        .unwrap()
                        .object
                        .native,
                    4u32.to_le_bytes()
                );
            }
            drop(page);
            drop(tree);
            let reopened = Jffs2Editor::open_compressed(
                flash(&source, &r),
                [7; 32],
                endian,
                limits(),
                profile,
                &r,
            )
            .unwrap();
            drop(reopened);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

fn compressed_trial(
    gc: bool,
    big: bool,
    codec: partmgr::fs_jffs2_builder::Jffs2BuildCompression,
    cut: Cut,
    persist: (bool, bool),
    recovery_cut: bool,
) -> (usize, usize, usize, usize) {
    let r = resources();
    let endian = if big {
        Jffs2Endian::Big
    } else {
        Jffs2Endian::Little
    };
    let profile = edit_compression(codec);
    let s = state(if big { convert_big(seed()) } else { seed() });
    let mut editor =
        Jffs2Editor::open_compressed(flash(&s, &r), [7; 32], endian, limits(), profile, &r)
            .unwrap();
    let initial = RangePayload::new(vec![b'A'; 512]);
    let plan = editor
        .write_range(&editor.identity(4).unwrap(), 0, &initial, 512, 40, &r)
        .unwrap();
    let j = state(vec![0; plan.journal_length() as usize]);
    editor.commit(plan, &mut Backend(j), &r).unwrap();
    let original = s.lock().unwrap().bytes.clone();
    s.lock().unwrap().writes = 0;
    s.lock().unwrap().flushes = 0;
    let plan = if gc {
        editor.collect(0, &r).unwrap()
    } else {
        let input = RangePayload::new(vec![b'C'; 64]);
        editor
            .write_range(&editor.identity(4).unwrap(), 8, &input, 600, 41, &r)
            .unwrap()
    };
    let expected_hash = plan.expected_sha256();
    let j = state(vec![0; plan.journal_length() as usize]);
    if recovery_cut {
        s.lock().unwrap().fail_write = Some(1);
    } else {
        set_multi_gc_cut(&s, &j, cut);
    }
    let result = editor.commit(plan, &mut Backend(j.clone()), &r);
    drop(editor.into_flash());
    let counts = if recovery_cut {
        assert!(result.is_err());
        crash(&s, persist.0);
        crash(&j, persist.1);
        set_multi_gc_cut(&s, &j, cut);
        let mut f = flash(&s, &r);
        let result = recover_compressed(
            &mut f,
            &mut Backend(j.clone()),
            [7; 32],
            endian,
            limits(),
            profile,
            &r,
        );
        if matches!(cut, Cut::None) {
            assert_eq!(result.unwrap().sha256, expected_hash);
        } else {
            assert!(result.is_err(), "{gc}/{big}/{codec:?}/{cut:?}");
        }
        drop(f);
        multi_gc_counts(&s, &j)
    } else {
        if matches!(cut, Cut::None) {
            assert_eq!(result.unwrap().sha256, expected_hash);
        } else {
            assert!(result.is_err(), "{gc}/{big}/{codec:?}/{cut:?}");
        }
        multi_gc_counts(&s, &j)
    };
    crash(&s, persist.0);
    crash(&j, persist.1);
    let mut f = flash(&s, &r);
    let before = s.lock().unwrap().bytes.clone();
    let journal_before = j.lock().unwrap().bytes.clone();
    assert!(
        recover(
            &mut f,
            &mut Backend(j.clone()),
            [7; 32],
            endian,
            limits(),
            &r
        )
        .is_err()
    );
    assert_eq!(s.lock().unwrap().writes, 0);
    assert_eq!(j.lock().unwrap().writes, 0);
    assert_eq!(s.lock().unwrap().bytes, before);
    assert_eq!(j.lock().unwrap().bytes, journal_before);
    let recovered = recover_compressed(
        &mut f,
        &mut Backend(j.clone()),
        [7; 32],
        endian,
        limits(),
        profile,
        &r,
    );
    let completed = match recovered {
        Ok(report) => {
            assert_eq!(report.sha256, expected_hash);
            true
        }
        Err(_) => {
            assert_eq!(
                s.lock().unwrap().bytes,
                original,
                "missing durable PREPARED cannot leave target mutation"
            );
            false
        }
    };
    if completed {
        s.lock().unwrap().writes = 0;
        j.lock().unwrap().writes = 0;
        assert_eq!(
            recover_compressed(
                &mut f,
                &mut Backend(j.clone()),
                [7; 32],
                endian,
                limits(),
                profile,
                &r
            )
            .unwrap()
            .sha256,
            expected_hash
        );
        assert_eq!(s.lock().unwrap().writes, 0);
        assert_eq!(j.lock().unwrap().writes, 0);
    }
    drop(f);
    let volume = Jffs2Volume::open_compressed(
        Arc::new(Immutable(s.lock().unwrap().bytes.clone())),
        geometry(),
        endian,
        limits().read,
        profile.read,
        &r,
    )
    .unwrap();
    assert!(audit(&volume, limits().audit, &r).unwrap().is_clean());
    let file = volume.open_file(4, &r).unwrap();
    let mut expected = vec![b'A'; 512];
    if completed && !gc {
        expected[8..72].fill(b'C');
        expected.resize(600, 0);
    }
    assert_eq!(
        read_all(&file, 1024, &r).unwrap().get().as_slice(),
        expected
    );
    drop(file);
    drop(volume);
    assert_eq!(r.memory.used(), 0);
    counts
}

#[test]
fn compressed_range_gc_mutation_and_recovery_cuts_all_four_persistence_profiles() {
    use partmgr::fs_jffs2_builder::Jffs2BuildCompression;
    for gc in [false, true] {
        for big in [false, true] {
            for codec in [Jffs2BuildCompression::Rtime, Jffs2BuildCompression::Zlib] {
                for recovery in [false, true] {
                    let (tw, tf, jw, jf) =
                        compressed_trial(gc, big, codec, Cut::None, (true, true), recovery);
                    for persist in [(false, false), (false, true), (true, false), (true, true)] {
                        for n in 1..=tw {
                            compressed_trial(
                                gc,
                                big,
                                codec,
                                Cut::TargetWrite(n),
                                persist,
                                recovery,
                            );
                        }
                        for n in 1..=tf {
                            compressed_trial(
                                gc,
                                big,
                                codec,
                                Cut::TargetFlush(n),
                                persist,
                                recovery,
                            );
                        }
                        for n in 1..=jw {
                            compressed_trial(
                                gc,
                                big,
                                codec,
                                Cut::JournalWrite(n),
                                persist,
                                recovery,
                            );
                        }
                        for n in 1..=jf {
                            compressed_trial(
                                gc,
                                big,
                                codec,
                                Cut::JournalFlush(n),
                                persist,
                                recovery,
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn rehashed_compressed_gc_profiles_payload_sizes_and_metadata_reject_without_any_writes() {
    use partmgr::fs_jffs2_builder::Jffs2BuildCompression;
    for big in [false, true] {
        for codec in [Jffs2BuildCompression::Rtime, Jffs2BuildCompression::Zlib] {
            for case in 0..5 {
                let r = resources();
                let endian = if big {
                    Jffs2Endian::Big
                } else {
                    Jffs2Endian::Little
                };
                let profile = edit_compression(codec);
                let s = state(if big { convert_big(seed()) } else { seed() });
                let mut editor = Jffs2Editor::open_compressed(
                    flash(&s, &r),
                    [7; 32],
                    endian,
                    limits(),
                    profile,
                    &r,
                )
                .unwrap();
                let payload = RangePayload::new(vec![b'A'; 512]);
                let plan = editor
                    .write_range(&editor.identity(4).unwrap(), 0, &payload, 512, 40, &r)
                    .unwrap();
                let j = state(vec![0; plan.journal_length() as usize]);
                editor.commit(plan, &mut Backend(j), &r).unwrap();
                let baseline = s.lock().unwrap().bytes.clone();
                let plan = editor.collect(0, &r).unwrap();
                let j = state(vec![0; plan.journal_length() as usize]);
                s.lock().unwrap().writes = 0;
                s.lock().unwrap().flushes = 0;
                s.lock().unwrap().fail_write = Some(1);
                editor
                    .commit(plan, &mut Backend(j.clone()), &r)
                    .unwrap_err();
                drop(editor.into_flash());
                crash(&s, true);
                crash(&j, true);
                {
                    let mut j = j.lock().unwrap();
                    if case == 0 {
                        j.bytes[264] ^= 1;
                    } else if case == 1 {
                        j.bytes[236] = 7;
                    } else {
                        let count = u32::from_le_bytes(j.bytes[180..184].try_into().unwrap());
                        let dword = |b: &[u8], p: usize| {
                            if big {
                                u32::from_be_bytes(b[p..p + 4].try_into().unwrap())
                            } else {
                                u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
                            }
                        };
                        let mut cursor = 1024;
                        let mut changed = false;
                        for _ in 0..count {
                            let len = q(&j.bytes, cursor + 8) as usize;
                            cursor += 16;
                            let node = &mut j.bytes[cursor..cursor + len];
                            if node.len() >= 68 && dword(node, 12) == 4 && dword(node, 48) > 0 {
                                match case {
                                    2 => node[68] ^= 1, // Valid RTIME literal/NONE data, changed live GC content.
                                    3 => {
                                        let size = dword(node, 52);
                                        fixture::dword(node, 52, size + 1, big);
                                    }
                                    4 => node[24] ^= 1,
                                    _ => unreachable!(),
                                }
                                let encoded = dword(node, 48) as usize;
                                let checksum = fixture::crc(&node[68..68 + encoded]);
                                fixture::dword(node, 60, checksum, big);
                                let checksum = fixture::crc(&node[..60]);
                                fixture::dword(node, 64, checksum, big);
                                changed = true;
                                break;
                            }
                            cursor += len;
                        }
                        assert!(changed);
                    }
                    refresh_intent(&mut j.bytes, &baseline);
                }
                let before = s.lock().unwrap().bytes.clone();
                let journal_before = j.lock().unwrap().bytes.clone();
                let mut f = flash(&s, &r);
                assert!(
                    recover_compressed(
                        &mut f,
                        &mut Backend(j.clone()),
                        [7; 32],
                        endian,
                        limits(),
                        profile,
                        &r
                    )
                    .is_err(),
                    "{big}/{codec:?}/{case}"
                );
                assert_eq!(s.lock().unwrap().writes, 0);
                assert_eq!(j.lock().unwrap().writes, 0);
                assert_eq!(s.lock().unwrap().bytes, before);
                assert_eq!(j.lock().unwrap().bytes, journal_before);
                drop(f);
                assert_eq!(r.memory.used(), 0);
            }
        }
    }
}

#[test]
fn compressed_planning_codec_work_memory_source_faults_and_cancellation_refund_without_writes() {
    use partmgr::fs_jffs2_builder::Jffs2BuildCompression;
    for codec in [Jffs2BuildCompression::Rtime, Jffs2BuildCompression::Zlib] {
        for mode in 0..4 {
            let r = resources();
            let s = state(seed());
            let editor = Jffs2Editor::open_compressed(
                flash(&s, &r),
                [7; 32],
                Jffs2Endian::Little,
                limits(),
                edit_compression(codec),
                &r,
            )
            .unwrap();
            let input = FaultRangeSource {
                bytes: RangePayload::new(vec![b'A'; 5000]),
                changed: ObjectId {
                    source: 99,
                    generation: 2,
                    native: vec![2],
                },
                reads: std::sync::atomic::AtomicUsize::new(0),
                mode,
            };
            let error = editor
                .write_range(&editor.identity(4).unwrap(), 0, &input, 5000, 44, &r)
                .err()
                .unwrap();
            assert_eq!(
                error.kind,
                match mode {
                    0 => ErrorKind::Io,
                    3 => ErrorKind::Cancelled,
                    _ => ErrorKind::StalePlan,
                }
            );
            if mode == 0 {
                assert!(error.source.is_some());
            }
            assert_eq!(s.lock().unwrap().writes, 0);
            drop(editor);
            assert_eq!(r.memory.used(), 0);
        }
        let r = resources();
        let s = state(seed());
        let mut profile = edit_compression(codec);
        profile.read.work = 0;
        let editor = Jffs2Editor::open_compressed(
            flash(&s, &r),
            [7; 32],
            Jffs2Endian::Little,
            limits(),
            profile,
            &r,
        )
        .unwrap();
        let input = RangePayload::new(vec![b'A'; 1024]);
        assert_eq!(
            editor
                .write_range(&editor.identity(4).unwrap(), 0, &input, 1024, 44, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(s.lock().unwrap().writes, 0);
        drop(editor);
        assert_eq!(r.memory.used(), 0);
        let r = resources();
        let s = state(seed());
        let editor = Jffs2Editor::open_compressed(
            flash(&s, &r),
            [7; 32],
            Jffs2Endian::Little,
            limits(),
            edit_compression(codec),
            &r,
        )
        .unwrap();
        let low = Resources {
            memory: Budget::new(if matches!(codec, Jffs2BuildCompression::Zlib) {
                2 << 20
            } else {
                200000
            }),
            cancellation: Cancellation::default(),
        };
        assert_eq!(
            editor
                .write_range(&editor.identity(4).unwrap(), 0, &input, 1024, 44, &low)
                .err()
                .unwrap()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(s.lock().unwrap().writes, 0);
        assert_eq!(low.memory.used(), 0);
        drop(editor);
        assert_eq!(r.memory.used(), 0);
    }
}
fn interrupted_recovery(gc: bool, cut: Cut, persist: (bool, bool)) -> (usize, usize, usize, usize) {
    interrupted_recovery_for(gc, 0, cut, persist)
}
fn interrupted_recovery_for(
    gc: bool,
    victim: u64,
    cut: Cut,
    persist: (bool, bool),
) -> (usize, usize, usize, usize) {
    let (s, j, r) = prepared_for(gc, victim);
    let expected: [u8; 32] = j.lock().unwrap().bytes[128..160].try_into().unwrap();
    crash(&s, persist.0);
    crash(&j, persist.1);
    match cut {
        Cut::TargetWrite(n) => s.lock().unwrap().fail_write = Some(n),
        Cut::TargetFlush(n) => s.lock().unwrap().fail_flush = Some(n),
        Cut::JournalWrite(n) => j.lock().unwrap().fail_write = Some(n),
        Cut::JournalFlush(n) => j.lock().unwrap().fail_flush = Some(n),
        Cut::None => {}
    }
    let mut f = flash(&s, &r);
    let result = recover(
        &mut f,
        &mut Backend(j.clone()),
        [7; 32],
        Jffs2Endian::Little,
        limits(),
        &r,
    );
    let counts = {
        let s = s.lock().unwrap();
        let j = j.lock().unwrap();
        (s.writes, s.flushes, j.writes, j.flushes)
    };
    drop(f);
    if matches!(cut, Cut::None) {
        assert_eq!(result.unwrap().sha256, expected);
        return counts;
    }
    assert!(result.unwrap_err().source.source.is_some(), "{cut:?}");
    crash(&s, persist.0);
    crash(&j, persist.1);
    let mut f = flash(&s, &r);
    let report = recover(
        &mut f,
        &mut Backend(j.clone()),
        [7; 32],
        Jffs2Endian::Little,
        limits(),
        &r,
    )
    .unwrap();
    assert_eq!(report.sha256, expected);
    assert_payload(
        &s.lock().unwrap().bytes,
        if gc { b"original" } else { b"new" },
        &r,
    );
    let count = s.lock().unwrap().writes;
    assert_eq!(
        recover(
            &mut f,
            &mut Backend(j),
            [7; 32],
            Jffs2Endian::Little,
            limits(),
            &r
        )
        .unwrap()
        .accepted_bytes,
        0
    );
    assert_eq!(s.lock().unwrap().writes, count);
    drop(f);
    assert_eq!(r.memory.used(), 0);
    counts
}
#[test]
fn recovery_itself_can_be_interrupted_at_every_boundary_then_restarted_with_both_persistence_extremes()
 {
    for gc in [false, true] {
        let (tw, tf, jw, jf) = interrupted_recovery(gc, Cut::None, (true, true));
        for persist in [(false, false), (false, true), (true, false), (true, true)] {
            for n in 1..=tw {
                interrupted_recovery(gc, Cut::TargetWrite(n), persist);
            }
            for n in 1..=tf {
                interrupted_recovery(gc, Cut::TargetFlush(n), persist);
            }
            for n in 1..=jw {
                interrupted_recovery(gc, Cut::JournalWrite(n), persist);
            }
            for n in 1..=jf {
                interrupted_recovery(gc, Cut::JournalFlush(n), persist);
            }
        }
    }
}
fn big_seed() -> Vec<u8> {
    convert_big(seed())
}
fn convert_big(mut image: Vec<u8>) -> Vec<u8> {
    let mut p = 0;
    while p < image.len() {
        if image[p..p + 4] == [255; 4] {
            p += 4;
            continue;
        }
        let kind = u16::from_le_bytes(image[p + 2..p + 4].try_into().unwrap());
        let len = u32::from_le_bytes(image[p + 4..p + 8].try_into().unwrap()) as usize;
        let b = &mut image[p..p + len];
        let positions = match kind {
            0xe002 => vec![4, 12, 16, 20, 28, 32, 36, 40, 44, 48, 52, 60],
            0xe001 => vec![4, 12, 16, 20, 24, 36],
            0x2003 => vec![4],
            _ => panic!("independent fixture type"),
        };
        for at in positions {
            let n = u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
            b[at..at + 4].copy_from_slice(&n.to_be_bytes());
        }
        if kind == 0xe002 {
            for at in [24, 26, 58] {
                let n = u16::from_le_bytes(b[at..at + 2].try_into().unwrap());
                b[at..at + 2].copy_from_slice(&n.to_be_bytes());
            }
        }
        b[..2].copy_from_slice(&0x1985u16.to_be_bytes());
        b[2..4].copy_from_slice(&kind.to_be_bytes());
        let c = fixture::crc(&b[..8]);
        b[8..12].copy_from_slice(&c.to_be_bytes());
        if kind == 0xe001 {
            if &b[40..] == b"payload" {
                b[40] = 255;
            }
            let c = fixture::crc(&b[40..]);
            b[36..40].copy_from_slice(&c.to_be_bytes());
            let c = fixture::crc(&b[..32]);
            b[32..36].copy_from_slice(&c.to_be_bytes());
        }
        if kind == 0xe002 {
            let c = fixture::crc(&b[..60]);
            b[64..68].copy_from_slice(&c.to_be_bytes());
        }
        p += (len + 3) & !3;
    }
    image
}
#[test]
fn big_endian_native_non_utf8_append_and_gc() {
    let r = resources();
    let s = state(big_seed());
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Big, limits(), &r).unwrap();
    let name = b"\xffayload";
    let payload = (0..333).map(|n| (n % 251) as u8).collect::<Vec<_>>();
    let plan = editor
        .replace(&editor.identity(1).unwrap(), name, &payload, 39, &r)
        .unwrap();
    let j = state(vec![0; plan.journal_length() as usize]);
    editor.commit(plan, &mut Backend(j), &r).unwrap();
    let plan = editor.collect(0, &r).unwrap();
    let j = state(vec![0; plan.journal_length() as usize]);
    editor.commit(plan, &mut Backend(j), &r).unwrap();
    drop(editor);
    let volume = Jffs2Volume::open(
        Arc::new(Immutable(s.lock().unwrap().bytes.clone())),
        geometry(),
        Jffs2Endian::Big,
        limits().read,
        &r,
    )
    .unwrap();
    assert_eq!(
        read_all(&volume.open_file(101, &r).unwrap(), 2048, &r)
            .unwrap()
            .get()
            .as_slice(),
        payload
    );
    let tree =
        partmgr::fs_jffs2_tree::Jffs2TreeSource::inventory(volume, limits().audit, &r).unwrap();
    let page = tree.directory_page(&tree.root(), None, 64, &r).unwrap();
    assert!(
        page.entries
            .iter()
            .any(|e| e.name == NativeName::Bytes(name.to_vec()))
    );
    let a = page
        .entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"alias-a".to_vec()))
        .unwrap();
    let b = page
        .entries
        .iter()
        .find(|e| e.name == NativeName::Bytes(b"alias-b".to_vec()))
        .unwrap();
    assert_eq!(a.object, b.object);
    drop(page);
    drop(tree);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn copied_victim_may_only_contain_valid_partial_erase_transitions() {
    let r = resources();
    let s = state(seed());
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let plan = editor.collect(0, &r).unwrap();
    let j = state(vec![0; plan.journal_length() as usize]); // Successful-copy program write count is discovered from the model.
    let (writes, _, _, _) = trial(true, Cut::None, (true, true));
    s.lock().unwrap().fail_write = Some(writes - 31); // Erase is 32 backend writes; cut its first one.
    editor
        .commit(plan, &mut Backend(j.clone()), &r)
        .unwrap_err();
    assert_eq!(
        u32::from_le_bytes(
            j.lock().unwrap().bytes[512 + 16..512 + 20]
                .try_into()
                .unwrap()
        ),
        2
    );
    drop(editor.into_flash());
    crash(&s, true);
    crash(&j, true);
    s.lock().unwrap().bytes[4] = 0;
    let mut f = flash(&s, &r);
    assert!(
        recover(
            &mut f,
            &mut Backend(j.clone()),
            [7; 32],
            Jffs2Endian::Little,
            limits(),
            &r
        )
        .is_err()
    );
    assert_eq!(s.lock().unwrap().writes, 0);
    assert_eq!(j.lock().unwrap().writes, 0);
    drop(f);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn namespace_create_links_move_unlink_and_symlink_gc_preserve_reachable_objects() {
    for big in [false, true] {
        let r = resources();
        let mut bytes = if big { big_seed() } else { seed() };
        bytes.resize(32 * 4096, 255);
        let s = state(bytes);
        let mut editor = Jffs2Editor::open(
            flash(&s, &r),
            [7; 32],
            if big {
                Jffs2Endian::Big
            } else {
                Jffs2Endian::Little
            },
            limits(),
            &r,
        )
        .unwrap();
        let meta = Jffs2CreateMetadata {
            permissions: 0o750,
            uid: 17,
            gid: 23,
            accessed: 10,
            modified: 20,
            changed: 30,
        };
        let apply = |plan: Jffs2EditPlan, editor: &mut Jffs2Editor<FlashImage<Backend>>| {
            let j = state(vec![0; plan.journal_length() as usize]);
            editor.commit(plan, &mut Backend(j), &r).unwrap();
        };
        apply(
            editor
                .create_directory(&editor.identity(1).unwrap(), b"dir", meta, &r)
                .unwrap(),
            &mut editor,
        );
        apply(
            editor
                .create_file(
                    &editor.identity(101).unwrap(),
                    b"\xfffile",
                    b"created content",
                    meta,
                    &r,
                )
                .unwrap(),
            &mut editor,
        );
        apply(
            editor
                .link(
                    &editor.identity(102).unwrap(),
                    &editor.identity(1).unwrap(),
                    b"linked",
                    40,
                    &r,
                )
                .unwrap(),
            &mut editor,
        );
        assert!(
            editor
                .unlink(&editor.identity(1).unwrap(), b"dir", 41, &r)
                .is_err()
        );
        assert!(
            editor
                .link(
                    &editor.identity(101).unwrap(),
                    &editor.identity(1).unwrap(),
                    b"bad-directory-link",
                    41,
                    &r
                )
                .is_err()
        );
        apply(
            editor
                .rename(
                    &editor.identity(101).unwrap(),
                    b"\xfffile",
                    &editor.identity(1).unwrap(),
                    b"moved",
                    42,
                    &r,
                )
                .unwrap(),
            &mut editor,
        );
        apply(
            editor
                .unlink(&editor.identity(1).unwrap(), b"linked", 43, &r)
                .unwrap(),
            &mut editor,
        );
        assert!(editor.identity(102).is_ok());
        apply(
            editor
                .unlink(&editor.identity(1).unwrap(), b"moved", 44, &r)
                .unwrap(),
            &mut editor,
        );
        assert!(editor.identity(102).is_err());
        apply(
            editor
                .unlink(&editor.identity(1).unwrap(), b"dir", 45, &r)
                .unwrap(),
            &mut editor,
        );
        assert!(editor.identity(101).is_err());
        apply(
            editor
                .create_symlink(
                    &editor.identity(1).unwrap(),
                    b"symlink",
                    b"../\xfftarget",
                    meta,
                    &r,
                )
                .unwrap(),
            &mut editor,
        );
        apply(editor.collect(4 * 4096, &r).unwrap(), &mut editor);
        let v = Jffs2Volume::open(
            Arc::new(Immutable(s.lock().unwrap().bytes.clone())),
            geometry(),
            if big {
                Jffs2Endian::Big
            } else {
                Jffs2Endian::Little
            },
            limits().read,
            &r,
        )
        .unwrap();
        assert!(audit(&v, limits().audit, &r).unwrap().is_clean());
        let raw = v.inode(103).unwrap().raw_metadata();
        let dword = |at| {
            let bytes: [u8; 4] = raw[at..at + 4].try_into().unwrap();
            if big {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            }
        };
        let word = |at| {
            let bytes: [u8; 2] = raw[at..at + 2].try_into().unwrap();
            if big {
                u16::from_be_bytes(bytes)
            } else {
                u16::from_le_bytes(bytes)
            }
        };
        assert_eq!(dword(20), 0xa000 | 0o750);
        assert_eq!((word(24), word(26)), (17, 23));
        assert_eq!((dword(32), dword(36), dword(40)), (10, 20, 30));

        drop(v);
        drop(editor);
        assert_eq!(r.memory.used(), 0);
    }
}

fn namespace_fault_trial(
    op: Jffs2EditOperation,
    cut: Cut,
    persist: (bool, bool),
) -> (usize, usize, usize, usize) {
    namespace_fault_trial_with_resize(op, false, cut, persist)
}
fn namespace_fault_trial_with_resize(
    op: Jffs2EditOperation,
    resize: bool,
    cut: Cut,
    persist: (bool, bool),
) -> (usize, usize, usize, usize) {
    let r = resources();
    let original = seed();
    let s = state(original.clone());
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let root = editor.identity(1).unwrap();
    let metadata = Jffs2CreateMetadata {
        permissions: 0o640,
        uid: 1,
        gid: 2,
        accessed: 3,
        modified: 4,
        changed: 5,
    };
    let plan = if resize {
        editor.truncate(&editor.identity(4).unwrap(), 3, 31, &r)
    } else {
        match op {
            Jffs2EditOperation::Create => {
                editor.create_file(&root, b"created", b"bounded payload", metadata, &r)
            }
            Jffs2EditOperation::Rename => {
                editor.rename(&root, b"payload", &root, b"renamed", 31, &r)
            }
            Jffs2EditOperation::Unlink => editor.unlink(&root, b"alias-a", 31, &r),
            Jffs2EditOperation::Link => {
                editor.link(&editor.identity(2).unwrap(), &root, b"linked", 31, &r)
            }
            Jffs2EditOperation::FileRange => editor.write_range(
                &editor.identity(4).unwrap(),
                2,
                &RangePayload::new(vec![7; 5000]),
                6000,
                31,
                &r,
            ),
            _ => unreachable!(),
        }
    }
    .unwrap();
    let expected = plan.expected_sha256();
    let j = state(vec![0; plan.journal_length() as usize]);
    match cut {
        Cut::TargetWrite(n) => s.lock().unwrap().fail_write = Some(n),
        Cut::TargetFlush(n) => s.lock().unwrap().fail_flush = Some(n),
        Cut::JournalWrite(n) => j.lock().unwrap().fail_write = Some(n),
        Cut::JournalFlush(n) => j.lock().unwrap().fail_flush = Some(n),
        Cut::None => {}
    }
    let result = editor.commit(plan, &mut Backend(j.clone()), &r);
    let counts = {
        let s = s.lock().unwrap();
        let j = j.lock().unwrap();
        (s.writes, s.flushes, j.writes, j.flushes)
    };
    if matches!(cut, Cut::None) {
        assert!(result.is_ok());
        drop(editor);
        assert_eq!(r.memory.used(), 0);
        return counts;
    }
    assert!(result.is_err(), "{op:?} {cut:?}");
    let target_writes = s.lock().unwrap().writes;
    drop(editor.into_flash());
    crash(&s, persist.0);
    crash(&j, persist.1);
    let mut reopened = flash(&s, &r);
    match recover(
        &mut reopened,
        &mut Backend(j.clone()),
        [7; 32],
        Jffs2Endian::Little,
        limits(),
        &r,
    ) {
        Ok(report) => {
            assert_eq!(report.sha256, expected);
            let before_counts = (s.lock().unwrap().writes, j.lock().unwrap().writes);
            assert_eq!(
                recover(
                    &mut reopened,
                    &mut Backend(j.clone()),
                    [7; 32],
                    Jffs2Endian::Little,
                    limits(),
                    &r
                )
                .unwrap()
                .sha256,
                expected
            );
            assert_eq!(
                before_counts,
                (s.lock().unwrap().writes, j.lock().unwrap().writes)
            );
        }
        Err(_) => {
            assert_eq!(target_writes, 0);
            assert_eq!(s.lock().unwrap().bytes, original);
            assert_eq!(s.lock().unwrap().writes, 0);
        }
    }
    drop(reopened);
    assert_eq!(r.memory.used(), 0);
    counts
}
#[test]
fn namespace_all_program_journal_flush_cuts_recover_under_four_persistence_combinations() {
    for op in [
        Jffs2EditOperation::Create,
        Jffs2EditOperation::Rename,
        Jffs2EditOperation::Unlink,
        Jffs2EditOperation::Link,
        Jffs2EditOperation::FileRange,
    ] {
        let counts = namespace_fault_trial(op, Cut::None, (true, true));
        for persist in [(false, false), (false, true), (true, false), (true, true)] {
            for n in 1..=counts.0 {
                namespace_fault_trial(op, Cut::TargetWrite(n), persist);
            }
            for n in 1..=counts.1 {
                namespace_fault_trial(op, Cut::TargetFlush(n), persist);
            }
            for n in 1..=counts.2 {
                namespace_fault_trial(op, Cut::JournalWrite(n), persist);
            }
            for n in 1..=counts.3 {
                namespace_fault_trial(op, Cut::JournalFlush(n), persist);
            }
        }
    }
}

#[test]
fn namespace_cycle_collisions_foreign_stale_ids_and_invalid_names_fail_before_writes() {
    let r = resources();
    let mut bytes = seed();
    bytes.resize(16 * 4096, 255);
    let s = state(bytes);
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let meta = Jffs2CreateMetadata {
        permissions: 0o755,
        uid: 0,
        gid: 0,
        accessed: 0,
        modified: 1,
        changed: 1,
    };
    let stale = editor.identity(1).unwrap();
    let plan = editor
        .create_directory(&stale, b"parent", meta, &r)
        .unwrap();
    let j = state(vec![0; plan.journal_length() as usize]);
    editor.commit(plan, &mut Backend(j), &r).unwrap();
    assert!(editor.create_directory(&stale, b"stale", meta, &r).is_err());
    let plan = editor
        .create_directory(&editor.identity(101).unwrap(), b"child", meta, &r)
        .unwrap();
    let j = state(vec![0; plan.journal_length() as usize]);
    editor.commit(plan, &mut Backend(j), &r).unwrap();
    let writes = s.lock().unwrap().writes;
    assert!(
        editor
            .rename(
                &editor.identity(1).unwrap(),
                b"parent",
                &editor.identity(102).unwrap(),
                b"cycle",
                2,
                &r
            )
            .is_err()
    );
    assert!(
        editor
            .rename(
                &editor.identity(1).unwrap(),
                b"payload",
                &editor.identity(1).unwrap(),
                b"other",
                2,
                &r
            )
            .is_err()
    );
    for name in [
        &b""[..],
        &b"."[..],
        &b".."[..],
        &b"bad/name"[..],
        &b"nul\0name"[..],
    ] {
        assert!(
            editor
                .create_file(&editor.identity(1).unwrap(), name, b"x", meta, &r)
                .is_err()
        );
    }
    let other = state(seed());
    let foreign = Jffs2Editor::open(
        flash(&other, &r),
        [7; 32],
        Jffs2Endian::Little,
        limits(),
        &r,
    )
    .unwrap();
    assert!(
        editor
            .link(
                &foreign.identity(2).unwrap(),
                &editor.identity(1).unwrap(),
                b"foreign",
                2,
                &r
            )
            .is_err()
    );
    assert_eq!(s.lock().unwrap().writes, writes);
    drop(foreign);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}

fn prepared_namespace(op: Jffs2EditOperation) -> (Arc<Mutex<State>>, Arc<Mutex<State>>, Resources) {
    prepared_namespace_with_resize(op, false)
}
fn prepared_namespace_with_resize(
    op: Jffs2EditOperation,
    resize: bool,
) -> (Arc<Mutex<State>>, Arc<Mutex<State>>, Resources) {
    let r = resources();
    let original = seed();
    let s = state(original.clone());
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let root = editor.identity(1).unwrap();
    let metadata = Jffs2CreateMetadata {
        permissions: 0o640,
        uid: 1,
        gid: 2,
        accessed: 3,
        modified: 4,
        changed: 5,
    };
    let plan = if resize {
        editor.truncate(&editor.identity(4).unwrap(), 3, 31, &r)
    } else {
        match op {
            Jffs2EditOperation::Create => {
                editor.create_file(&root, b"created", b"bounded payload", metadata, &r)
            }
            Jffs2EditOperation::Rename => {
                editor.rename(&root, b"payload", &root, b"renamed", 31, &r)
            }
            Jffs2EditOperation::Unlink => editor.unlink(&root, b"alias-a", 31, &r),
            Jffs2EditOperation::Link => {
                editor.link(&editor.identity(2).unwrap(), &root, b"linked", 31, &r)
            }
            Jffs2EditOperation::FileRange => editor.write_range(
                &editor.identity(4).unwrap(),
                2,
                &RangePayload::new(vec![7; 5000]),
                6000,
                31,
                &r,
            ),
            _ => unreachable!(),
        }
    }
    .unwrap();
    let j = state(vec![0; plan.journal_length() as usize]);
    s.lock().unwrap().fail_write = Some(1);
    editor
        .commit(plan, &mut Backend(j.clone()), &r)
        .unwrap_err();
    drop(editor.into_flash());
    crash(&s, true);
    crash(&j, true);
    (s, j, r)
}

fn interrupted_namespace_recovery(
    op: Jffs2EditOperation,
    cut: Cut,
    persist: (bool, bool),
) -> (usize, usize, usize, usize) {
    interrupted_namespace_recovery_with_resize(op, false, cut, persist)
}
fn interrupted_namespace_recovery_with_resize(
    op: Jffs2EditOperation,
    resize: bool,
    cut: Cut,
    persist: (bool, bool),
) -> (usize, usize, usize, usize) {
    let (s, j, r) = prepared_namespace_with_resize(op, resize);
    let expected: [u8; 32] = j.lock().unwrap().bytes[128..160].try_into().unwrap();
    crash(&s, persist.0);
    crash(&j, persist.1);
    match cut {
        Cut::TargetWrite(n) => s.lock().unwrap().fail_write = Some(n),
        Cut::TargetFlush(n) => s.lock().unwrap().fail_flush = Some(n),
        Cut::JournalWrite(n) => j.lock().unwrap().fail_write = Some(n),
        Cut::JournalFlush(n) => j.lock().unwrap().fail_flush = Some(n),
        Cut::None => {}
    }
    let mut f = flash(&s, &r);
    let result = recover(
        &mut f,
        &mut Backend(j.clone()),
        [7; 32],
        Jffs2Endian::Little,
        limits(),
        &r,
    );
    let counts = {
        let s = s.lock().unwrap();
        let j = j.lock().unwrap();
        (s.writes, s.flushes, j.writes, j.flushes)
    };
    drop(f);
    if matches!(cut, Cut::None) {
        assert_eq!(result.unwrap().sha256, expected);
        return counts;
    }
    assert!(result.unwrap_err().source.source.is_some(), "{cut:?}");
    crash(&s, persist.0);
    crash(&j, persist.1);
    let mut f = flash(&s, &r);
    let report = recover(
        &mut f,
        &mut Backend(j.clone()),
        [7; 32],
        Jffs2Endian::Little,
        limits(),
        &r,
    )
    .unwrap();
    assert_eq!(report.sha256, expected);
    let count = s.lock().unwrap().writes;
    assert_eq!(
        recover(
            &mut f,
            &mut Backend(j),
            [7; 32],
            Jffs2Endian::Little,
            limits(),
            &r
        )
        .unwrap()
        .accepted_bytes,
        0
    );
    assert_eq!(s.lock().unwrap().writes, count);
    drop(f);
    assert_eq!(r.memory.used(), 0);
    counts
}

#[test]
fn namespace_recovery_cuts_restart_under_independent_volatile_persistence() {
    for op in [
        Jffs2EditOperation::Create,
        Jffs2EditOperation::Rename,
        Jffs2EditOperation::Unlink,
        Jffs2EditOperation::Link,
        Jffs2EditOperation::FileRange,
    ] {
        let counts = interrupted_namespace_recovery(op, Cut::None, (true, true));
        for persist in [(false, false), (false, true), (true, false), (true, true)] {
            for n in 1..=counts.0 {
                interrupted_namespace_recovery(op, Cut::TargetWrite(n), persist);
            }
            for n in 1..=counts.1 {
                interrupted_namespace_recovery(op, Cut::TargetFlush(n), persist);
            }
            for n in 1..=counts.2 {
                interrupted_namespace_recovery(op, Cut::JournalWrite(n), persist);
            }
            for n in 1..=counts.3 {
                interrupted_namespace_recovery(op, Cut::JournalFlush(n), persist);
            }
        }
    }
}

#[test]
fn complete_symlink_histories_select_latest_and_gc_both_endians_reject_partial_history() {
    for big in [false, true] {
        let r = resources();
        let mut bytes = seed();
        let mut newer = node(5, 0xa000, b"../new-target");
        d(&mut newer, 16, 2);
        let c = fixture::crc(&newer[..60]);
        d(&mut newer, 64, c);
        bytes[4096 + 12..4096 + 12 + newer.len()].copy_from_slice(&newer);
        if big {
            bytes = convert_big(bytes);
        }
        let endian = if big {
            Jffs2Endian::Big
        } else {
            Jffs2Endian::Little
        };
        let s = state(bytes);
        let mut editor = Jffs2Editor::open(flash(&s, &r), [7; 32], endian, limits(), &r).unwrap();
        let plan = editor.collect(4 * 4096, &r).unwrap();
        let j = state(vec![0; plan.journal_length() as usize]);
        editor.commit(plan, &mut Backend(j), &r).unwrap();
        let v = Jffs2Volume::open(
            Arc::new(Immutable(s.lock().unwrap().bytes.clone())),
            geometry(),
            endian,
            limits().read,
            &r,
        )
        .unwrap();
        let file = v.open_file(5, &r).unwrap();
        assert_eq!(
            partmgr::fs_core::read_all(&file, 254, &r)
                .unwrap()
                .get()
                .as_slice(),
            b"../new-target"
        );
        drop(file);
        drop(v);
        drop(editor);
        assert_eq!(r.memory.used(), 0);
    }
    for bad in 0..4 {
        let r = resources();
        let mut bytes = seed();
        let mut newer = node(5, 0xa000, b"new");
        d(&mut newer, 16, 2);
        match bad {
            0 => d(&mut newer, 44, 1),
            1 => d(&mut newer, 28, 4),
            2 => newer[56] = 1,
            3 => {
                newer[68] = 0;
                let c = fixture::crc(&newer[68..71]);
                d(&mut newer, 60, c);
            }
            _ => unreachable!(),
        }
        let c = fixture::crc(&newer[..60]);
        d(&mut newer, 64, c);
        bytes[4108..4108 + newer.len()].copy_from_slice(&newer);
        assert!(
            Jffs2Volume::open(
                Arc::new(Immutable(bytes)),
                geometry(),
                Jffs2Endian::Little,
                limits().read,
                &r
            )
            .is_err()
        );
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn rehashed_namespace_intents_reject_bad_versions_parents_and_publication_without_writes() {
    for op in [
        Jffs2EditOperation::Create,
        Jffs2EditOperation::Rename,
        Jffs2EditOperation::Unlink,
        Jffs2EditOperation::Link,
    ] {
        for case in 0..3 {
            let (s, j, r) = prepared_namespace(op);
            {
                let mut j = j.lock().unwrap();
                let b = &mut j.bytes;
                let first = 1040;
                let first_len = q(b, 1032) as usize;
                let last = if matches!(op, Jffs2EditOperation::Create | Jffs2EditOperation::Rename)
                {
                    first + first_len + 16
                } else {
                    first
                };
                if case == 0 {
                    d(b, 20, 0);
                } else {
                    d(
                        b,
                        last + if case == 1 { 16 } else { 12 },
                        if case == 1 { 0 } else { 999 },
                    );
                    let c = fixture::crc(&b[last..last + 32]);
                    d(b, last + 32, c);
                }
                refresh_intent(b, &seed());
            }
            let target_before = s.lock().unwrap().bytes.clone();
            let journal_before = j.lock().unwrap().bytes.clone();
            let mut f = flash(&s, &r);
            assert!(
                recover(
                    &mut f,
                    &mut Backend(j.clone()),
                    [7; 32],
                    Jffs2Endian::Little,
                    limits(),
                    &r
                )
                .is_err(),
                "{op:?} case{case}"
            );
            assert_eq!(s.lock().unwrap().writes, 0);
            assert_eq!(j.lock().unwrap().writes, 0);
            assert_eq!(s.lock().unwrap().bytes, target_before);
            assert_eq!(j.lock().unwrap().bytes, journal_before);
            drop(f);
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
fn live_symlink_gc_all_mutation_and_recovery_cuts_with_four_persistence_combinations() {
    for recovery in [false, true] {
        let trial = |cut, persist| {
            if recovery {
                interrupted_recovery_for(true, 4 * 4096, cut, persist)
            } else {
                trial_for(true, 4 * 4096, cut, persist)
            }
        };
        let counts = trial(Cut::None, (true, true));
        for persist in [(false, false), (false, true), (true, false), (true, true)] {
            for n in 1..=counts.0 {
                trial(Cut::TargetWrite(n), persist);
            }
            for n in 1..=counts.1 {
                trial(Cut::TargetFlush(n), persist);
            }
            for n in 1..=counts.2 {
                trial(Cut::JournalWrite(n), persist);
            }
            for n in 1..=counts.3 {
                trial(Cut::JournalFlush(n), persist);
            }
        }
    }
}

struct RangePayload {
    id: ObjectId,
    bytes: Vec<u8>,
}
impl RangePayload {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            id: ObjectId {
                source: 99,
                generation: 1,
                native: vec![1],
            },
            bytes,
        }
    }
}
impl FileRead for RangePayload {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, p: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        let n = out.len().min(self.bytes.len().saturating_sub(p as usize));
        out[..n].copy_from_slice(&self.bytes[p as usize..p as usize + n]);
        Ok(n)
    }
    fn visit_extents(
        &self,
        _: &Resources,
        _: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "range source does not expose allocation",
        ))
    }
}
fn assert_inode_payload(
    bytes: &[u8],
    endian: Jffs2Endian,
    number: u32,
    expected: &[u8],
    r: &Resources,
) {
    let v = Jffs2Volume::open(
        Arc::new(Immutable(bytes.to_vec())),
        geometry(),
        endian,
        limits().read,
        r,
    )
    .unwrap();
    assert!(audit(&v, limits().audit, r).unwrap().is_clean());
    assert_eq!(
        read_all(&v.open_file(number, r).unwrap(), expected.len() as u64, r)
            .unwrap()
            .get()
            .as_slice(),
        expected
    );
}
#[test]
fn historical_truncate_then_explicit_zero_extend_never_resurrects_old_tail_both_endians() {
    for big in [false, true] {
        let r = resources();
        let mut bytes = seed();
        let mut at = 4108;
        for (version, size) in [(2, 2), (3, 6)] {
            let mut n = node(4, 0x8000, b"");
            d(&mut n, 16, version);
            d(&mut n, 28, size);
            if version == 3 {
                n[56] = 1;
                d(&mut n, 44, 2);
                d(&mut n, 52, 4);
            }
            let c = fixture::crc(&n[..60]);
            d(&mut n, 64, c);
            bytes[at..at + n.len()].copy_from_slice(&n);
            at += n.len();
        }
        if big {
            bytes = convert_big(bytes);
        }
        assert_inode_payload(
            &bytes,
            if big {
                Jffs2Endian::Big
            } else {
                Jffs2Endian::Little
            },
            4,
            b"sh\0\0\0\0",
            &r,
        );
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn multi_node_range_preserves_hardlinks_metadata_and_sparse_truncate_extension() {
    for big in [false, true] {
        let r = resources();
        let mut bytes = if big { big_seed() } else { seed() };
        bytes.resize(32 * 4096, 255);
        let s = state(bytes);
        let endian = if big {
            Jffs2Endian::Big
        } else {
            Jffs2Endian::Little
        };
        let mut l = limits();
        l.file_bytes = 256;
        let mut editor = Jffs2Editor::open(flash(&s, &r), [7; 32], endian, l, &r).unwrap();
        let input = RangePayload::new((0..5000).map(|i| (i % 251) as u8).collect());
        let plan = editor
            .write_range(&editor.identity(4).unwrap(), 2, &input, 7000, 91, &r)
            .unwrap();
        let j = state(vec![0; plan.journal_length() as usize]);
        editor.commit(plan, &mut Backend(j), &r).unwrap();
        let mut expected = vec![0; 7000];
        expected[..2].copy_from_slice(b"sh");
        expected[2..5002].copy_from_slice(&input.bytes);
        assert_inode_payload(&s.lock().unwrap().bytes, endian, 4, &expected, &r);
        let v = Jffs2Volume::open(
            Arc::new(Immutable(s.lock().unwrap().bytes.clone())),
            geometry(),
            endian,
            l.read,
            &r,
        )
        .unwrap();
        let raw = v.inode(4).unwrap().raw_metadata();
        let dword = |at| {
            let b = raw[at..at + 4].try_into().unwrap();
            if big {
                u32::from_be_bytes(b)
            } else {
                u32::from_le_bytes(b)
            }
        };
        assert_eq!(
            (dword(20), dword(32), dword(36), dword(40)),
            (0x8000 | 0o640, 23, 91, 91)
        );
        let tree = partmgr::fs_jffs2_tree::Jffs2TreeSource::inventory(v, l.audit, &r).unwrap();
        let page = tree.directory_page(&tree.root(), None, 64, &r).unwrap();
        let a = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"alias-a".to_vec()))
            .unwrap();
        let b = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"alias-b".to_vec()))
            .unwrap();
        assert_eq!(a.object, b.object);
        drop(page);
        drop(tree);
        for size in [3, 6000] {
            let plan = editor
                .truncate(&editor.identity(4).unwrap(), size, 92, &r)
                .unwrap();
            let j = state(vec![0; plan.journal_length() as usize]);
            editor.commit(plan, &mut Backend(j), &r).unwrap();
        }
        let mut expected = vec![0; 6000];
        expected[..3].copy_from_slice(&[b's', b'h', 0]);
        assert_inode_payload(&s.lock().unwrap().bytes, endian, 4, &expected, &r);
        drop(editor);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn rehashed_multi_node_range_intents_reject_gaps_versions_sizes_and_metadata_without_writes() {
    for case in 0..5 {
        let (s, j, r) = prepared_namespace(Jffs2EditOperation::FileRange);
        {
            let mut j = j.lock().unwrap();
            let b = &mut j.bytes;
            let mut at = 1024;
            let count = u32::from_le_bytes(b[180..184].try_into().unwrap()) as usize;
            let mut nodes = Vec::new();
            for _ in 0..count {
                let len = q(b, at + 8) as usize;
                nodes.push((at + 16, len));
                at += 16 + len;
            }
            let (p, len) = if case == 4 {
                *nodes.last().unwrap()
            } else {
                nodes[1]
            };
            match case {
                0 => d(b, p + 44, 1),
                1 => d(b, p + 16, 2),
                2 => d(b, p + 28, 6001),
                3 => d(b, p + 36, 99),
                4 => d(b, p + 44, 1),
                _ => unreachable!(),
            }
            let c = fixture::crc(&b[p..p + 60]);
            d(b, p + 64, c);
            assert!(len >= 68);
            refresh_intent(b, &seed());
        }
        let before = s.lock().unwrap().bytes.clone();
        let journal_before = j.lock().unwrap().bytes.clone();
        let mut f = flash(&s, &r);
        assert!(
            recover(
                &mut f,
                &mut Backend(j.clone()),
                [7; 32],
                Jffs2Endian::Little,
                limits(),
                &r
            )
            .is_err()
        );
        assert_eq!(s.lock().unwrap().writes, 0);
        assert_eq!(j.lock().unwrap().writes, 0);
        assert_eq!(s.lock().unwrap().bytes, before);
        assert_eq!(j.lock().unwrap().bytes, journal_before);
        drop(f);
        assert_eq!(r.memory.used(), 0);
    }
}

struct FaultRangeSource {
    bytes: RangePayload,
    changed: ObjectId,
    reads: std::sync::atomic::AtomicUsize,
    mode: u8,
}
impl FileRead for FaultRangeSource {
    fn identity(&self) -> &ObjectId {
        if self.mode == 1 && self.reads.load(std::sync::atomic::Ordering::Relaxed) >= 2 {
            &self.changed
        } else {
            &self.bytes.id
        }
    }
    fn len(&self) -> u64 {
        self.bytes.len()
            - u64::from(
                self.mode == 2 && self.reads.load(std::sync::atomic::Ordering::Relaxed) >= 2,
            )
    }
    fn read_at(&self, p: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        let n = self
            .reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n >= 2 && self.mode == 0 {
            return Err(Error::io(
                "causal deferred range failure",
                io::Error::other("modeled source fault"),
            ));
        }
        if n >= 2 && self.mode == 3 {
            r.cancellation.cancel();
        }
        self.bytes.read_at(p, out, r)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.bytes.visit_extents(r, v)
    }
}
#[test]
fn multi_node_range_source_fault_identity_length_cancel_and_caps_never_mutate_target() {
    for mode in 0..4 {
        let r = resources();
        let s = state(seed());
        let mut l = limits();
        l.file_bytes = 256;
        let editor = Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, l, &r).unwrap();
        let payload = FaultRangeSource {
            bytes: RangePayload::new(vec![7; 5000]),
            changed: ObjectId {
                source: 99,
                generation: 2,
                native: vec![1],
            },
            reads: std::sync::atomic::AtomicUsize::new(0),
            mode,
        };
        let error = editor
            .write_range(&editor.identity(4).unwrap(), 2, &payload, 6000, 31, &r)
            .err()
            .unwrap();
        assert_eq!(
            error.kind,
            if mode == 0 {
                ErrorKind::Io
            } else if mode == 3 {
                ErrorKind::Cancelled
            } else {
                ErrorKind::StalePlan
            }
        );
        if mode == 0 {
            assert!(error.source.is_some());
        }
        assert_eq!(s.lock().unwrap().writes, 0);
        drop(editor);
        assert_eq!(r.memory.used(), 0);
    }
    let r = resources();
    let s = state(seed());
    let editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let input = RangePayload::new(vec![1; 5000]);
    let low = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        editor
            .write_range(&editor.identity(4).unwrap(), 0, &input, 5000, 31, &low)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert!(
        editor
            .write_range(&editor.identity(4).unwrap(), u64::MAX, &input, 5000, 31, &r)
            .is_err()
    );
    assert!(
        editor
            .truncate(
                &editor.identity(4).unwrap(),
                u64::from(u32::MAX) + 1,
                31,
                &r
            )
            .is_err()
    );
    assert!(
        editor
            .truncate(&editor.identity(1).unwrap(), 0, 31, &r)
            .is_err()
    );
    assert_eq!(s.lock().unwrap().writes, 0);
    assert_eq!(low.memory.used(), 0);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn metadata_only_truncate_mutation_and_recovery_cuts_cover_four_persistence_combinations() {
    for recovery in [false, true] {
        let trial = |cut, persist| {
            if recovery {
                interrupted_namespace_recovery_with_resize(
                    Jffs2EditOperation::FileRange,
                    true,
                    cut,
                    persist,
                )
            } else {
                namespace_fault_trial_with_resize(Jffs2EditOperation::FileRange, true, cut, persist)
            }
        };
        let counts = trial(Cut::None, (true, true));
        for persist in [(false, false), (false, true), (true, false), (true, true)] {
            for n in 1..=counts.0 {
                trial(Cut::TargetWrite(n), persist);
            }
            for n in 1..=counts.1 {
                trial(Cut::TargetFlush(n), persist);
            }
            for n in 1..=counts.2 {
                trial(Cut::JournalWrite(n), persist);
            }
            for n in 1..=counts.3 {
                trial(Cut::JournalFlush(n), persist);
            }
        }
    }
}
#[test]
fn sparse_gigabyte_extension_uses_bounded_zero_nodes_and_deferred_reads() {
    let r = resources();
    let s = state(seed());
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let plan = editor
        .truncate(&editor.identity(4).unwrap(), 1 << 30, 42, &r)
        .unwrap();
    assert!(plan.journal_length() < 2048);
    let j = state(vec![0; plan.journal_length() as usize]);
    editor.commit(plan, &mut Backend(j), &r).unwrap();
    drop(editor);
    let v = Jffs2Volume::open(
        Arc::new(Immutable(s.lock().unwrap().bytes.clone())),
        geometry(),
        Jffs2Endian::Little,
        limits().read,
        &r,
    )
    .unwrap();
    let file = v.open_file(4, &r).unwrap();
    assert_eq!(file.len(), 1 << 30);
    let mut out = [7; 128];
    assert_eq!(file.read_at((1 << 30) - 128, &mut out, &r).unwrap(), 128);
    assert_eq!(out, [0; 128]);
    assert!(r.memory.used() < 2 << 20);
    drop(file);
    drop(v);
    assert_eq!(r.memory.used(), 0);
}

struct AlternatingRangeIdentity {
    payload: RangePayload,
    changed: ObjectId,
    calls: std::sync::atomic::AtomicUsize,
}
impl FileRead for AlternatingRangeIdentity {
    fn identity(&self) -> &ObjectId {
        if self
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            == 0
        {
            &self.payload.id
        } else {
            &self.changed
        }
    }
    fn len(&self) -> u64 {
        self.payload.len()
    }
    fn read_at(&self, p: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        self.payload.read_at(p, out, r)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        self.payload.visit_extents(r, v)
    }
}
#[test]
fn alternating_identity_key_length_rejects_without_panic_or_target_writes() {
    let r = resources();
    let s = state(seed());
    let editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let source = AlternatingRangeIdentity {
        payload: RangePayload::new(vec![7; 5000]),
        changed: ObjectId {
            source: 99,
            generation: 2,
            native: vec![1; 31],
        },
        calls: std::sync::atomic::AtomicUsize::new(0),
    };
    assert_eq!(
        editor
            .write_range(&editor.identity(4).unwrap(), 2, &source, 6000, 31, &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::StalePlan
    );
    assert_eq!(s.lock().unwrap().writes, 0);
    drop(editor);
    assert_eq!(r.memory.used(), 0);
}

fn fragmented_gc_seed(big: bool) -> Vec<u8> {
    let mut image = seed();
    image.resize(12 * 4096, 255);
    let mut block = 1;
    let mut at = block * 4096 + 12;
    let mut version = 2;
    let mut records = Vec::new();
    for chunk in vec![7; 5000].chunks(1000) {
        let mut n = node(4, 0x8000, chunk);
        d(&mut n, 16, version);
        d(&mut n, 28, 6000);
        d(&mut n, 44, 2 + (version - 2) * 1000);
        let c = fixture::crc(&n[..60]);
        d(&mut n, 64, c);
        records.push(n);
        version += 1;
    }
    let mut zero = node(4, 0x8000, b"");
    d(&mut zero, 16, version);
    d(&mut zero, 28, 6000);
    d(&mut zero, 44, 5002);
    d(&mut zero, 52, 998);
    zero[56] = 1;
    let c = fixture::crc(&zero[..60]);
    d(&mut zero, 64, c);
    records.push(zero);
    version += 1;
    let mut metadata = node(4, 0x8000, b"");
    d(&mut metadata, 16, version);
    d(&mut metadata, 28, 6000);
    let c = fixture::crc(&metadata[..60]);
    d(&mut metadata, 64, c);
    records.push(metadata);
    for record in records {
        if at + record.len() > (block + 1) * 4096 {
            block += 1;
            at = block * 4096 + 12;
        }
        image[at..at + record.len()].copy_from_slice(&record);
        at += record.len();
    }
    if big { convert_big(image) } else { image }
}
#[test]
fn multi_node_gc_relocates_independent_fragmented_data_zero_maps_hardlinks_both_endians() {
    for big in [false, true] {
        let r = resources();
        let bytes = fragmented_gc_seed(big);
        let s = state(bytes.clone());
        let endian = if big {
            Jffs2Endian::Big
        } else {
            Jffs2Endian::Little
        };
        let mut l = limits();
        l.file_bytes = 256;
        let mut expected = vec![0; 6000];
        expected[..2].copy_from_slice(b"sh");
        expected[2..5002].fill(7);
        assert_inode_payload(&bytes, endian, 4, &expected, &r);
        let mut editor = Jffs2Editor::open(flash(&s, &r), [7; 32], endian, l, &r).unwrap();
        let plan = editor.collect(4096, &r).unwrap();
        let j = state(vec![0; plan.journal_length() as usize]);
        editor.commit(plan, &mut Backend(j), &r).unwrap();
        assert!(
            s.lock().unwrap().bytes[4096..8192]
                .iter()
                .all(|b| *b == 255)
        );
        assert_inode_payload(&s.lock().unwrap().bytes, endian, 4, &expected, &r);
        let v = Jffs2Volume::open(
            Arc::new(Immutable(s.lock().unwrap().bytes.clone())),
            geometry(),
            endian,
            l.read,
            &r,
        )
        .unwrap();
        let f = v.open_file(4, &r).unwrap();
        let mut holes = Vec::new();
        f.visit_extents(&r, &mut |e| {
            if matches!(e.kind, ExtentKind::Hole) {
                holes.push((e.offset, e.length));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(holes, vec![(5002, 998)]);
        drop(f);
        let tree = partmgr::fs_jffs2_tree::Jffs2TreeSource::inventory(v, l.audit, &r).unwrap();
        let page = tree.directory_page(&tree.root(), None, 64, &r).unwrap();
        let a = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"alias-a".to_vec()))
            .unwrap();
        let b = page
            .entries
            .iter()
            .find(|e| e.name == NativeName::Bytes(b"alias-b".to_vec()))
            .unwrap();
        assert_eq!(a.object, b.object);
        drop(page);
        drop(tree);
        drop(editor);
        assert_eq!(r.memory.used(), 0);
    }
}

fn multi_gc_trial(
    cut: Cut,
    persist: (bool, bool),
    recovery_cut: bool,
) -> (usize, usize, usize, usize) {
    let r = resources();
    let s = state(fragmented_gc_seed(false));
    let mut l = limits();
    l.file_bytes = 256;
    let mut editor = Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, l, &r).unwrap();
    let plan = editor.collect(4096, &r).unwrap();
    let expected = plan.expected_sha256();
    let j = state(vec![0; plan.journal_length() as usize]);
    if recovery_cut {
        s.lock().unwrap().fail_write = Some(1);
    } else {
        set_multi_gc_cut(&s, &j, cut);
    }
    let result = editor.commit(plan, &mut Backend(j.clone()), &r);
    drop(editor.into_flash());
    let counts = if recovery_cut {
        assert!(result.is_err());
        crash(&s, persist.0);
        crash(&j, persist.1);
        set_multi_gc_cut(&s, &j, cut);
        let mut f = flash(&s, &r);
        let result = recover(
            &mut f,
            &mut Backend(j.clone()),
            [7; 32],
            Jffs2Endian::Little,
            l,
            &r,
        );
        if matches!(cut, Cut::None) {
            assert_eq!(result.unwrap().sha256, expected);
        } else {
            assert!(result.is_err());
        }
        drop(f);
        multi_gc_counts(&s, &j)
    } else {
        if matches!(cut, Cut::None) {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
        multi_gc_counts(&s, &j)
    };
    crash(&s, persist.0);
    crash(&j, persist.1);
    let mut f = flash(&s, &r);
    let before = s.lock().unwrap().bytes.clone();
    let result = recover(
        &mut f,
        &mut Backend(j.clone()),
        [7; 32],
        Jffs2Endian::Little,
        l,
        &r,
    );
    match result {
        Ok(report) => {
            assert_eq!(report.sha256, expected);
            let mut payload = vec![0; 6000];
            payload[..2].copy_from_slice(b"sh");
            payload[2..5002].fill(7);
            assert_inode_payload(
                &s.lock().unwrap().bytes,
                Jffs2Endian::Little,
                4,
                &payload,
                &r,
            );
            let writes = s.lock().unwrap().writes;
            assert_eq!(
                recover(
                    &mut f,
                    &mut Backend(j.clone()),
                    [7; 32],
                    Jffs2Endian::Little,
                    l,
                    &r
                )
                .unwrap()
                .accepted_bytes,
                0
            );
            assert_eq!(s.lock().unwrap().writes, writes);
        }
        Err(_) => {
            assert!(!recovery_cut);
            assert_eq!(s.lock().unwrap().writes, 0);
            assert_eq!(s.lock().unwrap().bytes, before);
        }
    }
    drop(f);
    assert_eq!(r.memory.used(), 0);
    counts
}
fn set_multi_gc_cut(s: &Arc<Mutex<State>>, j: &Arc<Mutex<State>>, cut: Cut) {
    match cut {
        Cut::TargetWrite(n) => s.lock().unwrap().fail_write = Some(n),
        Cut::TargetFlush(n) => s.lock().unwrap().fail_flush = Some(n),
        Cut::JournalWrite(n) => j.lock().unwrap().fail_write = Some(n),
        Cut::JournalFlush(n) => j.lock().unwrap().fail_flush = Some(n),
        Cut::None => {}
    }
}
fn multi_gc_counts(s: &Arc<Mutex<State>>, j: &Arc<Mutex<State>>) -> (usize, usize, usize, usize) {
    let s = s.lock().unwrap();
    let j = j.lock().unwrap();
    (s.writes, s.flushes, j.writes, j.flushes)
}
#[test]
fn multi_node_gc_all_mutation_and_recovery_cuts_four_volatile_persistence_combinations() {
    for recovery in [false, true] {
        let (tw, tf, jw, jf) = multi_gc_trial(Cut::None, (true, true), recovery);
        for persist in [(false, false), (false, true), (true, false), (true, true)] {
            for n in 1..=tw {
                multi_gc_trial(Cut::TargetWrite(n), persist, recovery);
            }
            for n in 1..=tf {
                multi_gc_trial(Cut::TargetFlush(n), persist, recovery);
            }
            for n in 1..=jw {
                multi_gc_trial(Cut::JournalWrite(n), persist, recovery);
            }
            for n in 1..=jf {
                multi_gc_trial(Cut::JournalFlush(n), persist, recovery);
            }
        }
    }
}
#[test]
fn rehashed_multi_node_gc_groups_reject_gaps_versions_metadata_and_payload_without_writes() {
    for case in 0..6 {
        let r = resources();
        let original = fragmented_gc_seed(false);
        let s = state(original.clone());
        let mut l = limits();
        l.file_bytes = 256;
        let mut editor =
            Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, l, &r).unwrap();
        let plan = editor.collect(4096, &r).unwrap();
        let j = state(vec![0; plan.journal_length() as usize]);
        s.lock().unwrap().fail_write = Some(1);
        editor
            .commit(plan, &mut Backend(j.clone()), &r)
            .unwrap_err();
        drop(editor.into_flash());
        crash(&s, false);
        crash(&j, true);
        {
            let mut journal = j.lock().unwrap();
            let b = &mut journal.bytes;
            let count = u32::from_le_bytes(b[180..184].try_into().unwrap()) as usize;
            let mut at = 1024;
            let mut nodes = Vec::new();
            for _ in 0..count {
                let len = q(b, at + 8) as usize;
                nodes.push((at + 16, len));
                at += 16 + len;
            }
            let p = if case == 4 {
                nodes.last().unwrap().0
            } else {
                nodes[1].0
            };
            match case {
                0 => d(b, p + 44, 1),
                1 => d(b, p + 16, 1),
                2 => d(b, p + 28, 6001),
                3 => d(b, p + 36, 99),
                4 => d(b, p + 44, 1),
                5 => {
                    b[p + 68] ^= 1;
                    let c = fixture::crc(
                        &b[p + 68
                            ..p + 68
                                + u32::from_le_bytes(b[p + 48..p + 52].try_into().unwrap())
                                    as usize],
                    );
                    d(b, p + 60, c);
                }
                _ => unreachable!(),
            }
            let c = fixture::crc(&b[p..p + 60]);
            d(b, p + 64, c);
            refresh_intent(b, &original);
        }
        let before = s.lock().unwrap().bytes.clone();
        let jb = j.lock().unwrap().bytes.clone();
        let mut f = flash(&s, &r);
        assert!(
            recover(
                &mut f,
                &mut Backend(j.clone()),
                [7; 32],
                Jffs2Endian::Little,
                l,
                &r
            )
            .is_err(),
            "case {case}"
        );
        assert_eq!(s.lock().unwrap().writes, 0);
        assert_eq!(j.lock().unwrap().writes, 0);
        assert_eq!(s.lock().unwrap().bytes, before);
        assert_eq!(j.lock().unwrap().bytes, jb);
        drop(f);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn multi_node_gc_keeps_gigabyte_zero_extent_compact_and_caps_preflight_without_mutation() {
    let r = resources();
    let s = state(seed());
    let mut editor =
        Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, limits(), &r).unwrap();
    let plan = editor
        .truncate(&editor.identity(4).unwrap(), 1 << 30, 42, &r)
        .unwrap();
    let j = state(vec![0; plan.journal_length() as usize]);
    editor.commit(plan, &mut Backend(j), &r).unwrap();
    let low = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    let writes = s.lock().unwrap().writes;
    assert_eq!(
        editor.collect(4096, &low).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    let cancelled = resources();
    cancelled.cancellation.cancel();
    assert_eq!(
        editor.collect(4096, &cancelled).err().unwrap().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(s.lock().unwrap().writes, writes);
    let plan = editor.collect(4096, &r).unwrap();
    assert!(plan.journal_length() < 8192);
    let j = state(vec![0; plan.journal_length() as usize]);
    editor.commit(plan, &mut Backend(j), &r).unwrap();
    drop(editor);
    let v = Jffs2Volume::open(
        Arc::new(Immutable(s.lock().unwrap().bytes.clone())),
        geometry(),
        Jffs2Endian::Little,
        limits().read,
        &r,
    )
    .unwrap();
    let file = v.open_file(4, &r).unwrap();
    let mut out = [9; 128];
    file.read_at((1 << 30) - 128, &mut out, &r).unwrap();
    assert_eq!(out, [0; 128]);
    assert!(r.memory.used() < 2 << 20);
    drop(file);
    drop(v);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn packed_gc_layout_matches_independent_next_fit_model_and_capacity_rejects_without_writes() {
    // The independent history's original six-byte extent retains its end boundary
    // when the first patch overlays bytes 2..1002: segments 2, 4, then 996.
    let mut lengths = vec![72usize, 72, 324, 324, 324, 296];
    for _ in 0..4 {
        lengths.extend([324, 324, 324, 300]);
    }
    lengths.extend([68, 68]);
    let mut expected = Vec::new();
    let mut block = 5usize;
    let mut cursor = block * 4096 + 12;
    for &length in &lengths {
        if cursor + length > (block + 1) * 4096 {
            block += 1;
            cursor = block * 4096 + 12;
        }
        expected.push((cursor, length));
        cursor += length;
    }
    assert_eq!(block, 6);
    for available in [1usize, 2] {
        let r = resources();
        let mut image = fragmented_gc_seed(false);
        image.truncate((5 + available) * 4096);
        let s = state(image);
        let mut l = limits();
        l.file_bytes = 256;
        let mut editor =
            Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, l, &r).unwrap();
        let plan = editor.collect(4096, &r);
        if available == 1 {
            assert!(plan.is_err());
            assert_eq!(s.lock().unwrap().writes, 0);
            drop(editor);
            assert_eq!(r.memory.used(), 0);
            continue;
        }
        let plan = plan.unwrap();

        let j = state(vec![0; plan.journal_length() as usize]);
        s.lock().unwrap().fail_write = Some(1);
        editor
            .commit(plan, &mut Backend(j.clone()), &r)
            .unwrap_err();
        drop(editor.into_flash());
        let journal = j.lock().unwrap();
        let b = &journal.bytes;
        let count = u32::from_le_bytes(b[180..184].try_into().unwrap()) as usize;
        assert_eq!(count, lengths.len());
        let mut at = 1024;
        for &(offset, length) in &expected {
            assert_eq!((q(b, at) as usize, q(b, at + 8) as usize), (offset, length));
            at += 16 + length;
        }
        assert!(expected.windows(2).any(|w| w[0].0 + w[0].1 == w[1].0));
        drop(journal);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn torn_second_packed_node_keeps_completed_neighbor_and_recovers_four_persistence_combinations() {
    for persist in [(false, false), (false, true), (true, false), (true, true)] {
        let r = resources();
        let s = state(fragmented_gc_seed(false));
        let mut l = limits();
        l.file_bytes = 256;
        let mut editor =
            Jffs2Editor::open(flash(&s, &r), [7; 32], Jffs2Endian::Little, l, &r).unwrap();
        let plan = editor.collect(4096, &r).unwrap();
        let expected = plan.expected_sha256();
        let j = state(vec![0; plan.journal_length() as usize]);
        s.lock().unwrap().fail_write = Some(3);
        editor
            .commit(plan, &mut Backend(j.clone()), &r)
            .unwrap_err();
        drop(editor.into_flash());
        {
            let j = j.lock().unwrap();
            let b = &j.bytes;
            let first = q(b, 1024) as usize;
            let length = q(b, 1032) as usize;
            let next = 1040 + length;
            let second = q(b, next) as usize;
            assert_eq!(first + length, second);
            let s = s.lock().unwrap();
            assert_eq!(&s.bytes[first..first + length], &b[1040..1040 + length]);
            assert_eq!(&s.bytes[second..second + 12], &[255; 12]);
            assert_eq!(&s.bytes[second + 12..second + 16], &b[next + 28..next + 32]);
        }
        crash(&s, persist.0);
        crash(&j, persist.1);
        let mut f = flash(&s, &r);
        assert_eq!(
            recover(
                &mut f,
                &mut Backend(j.clone()),
                [7; 32],
                Jffs2Endian::Little,
                l,
                &r
            )
            .unwrap()
            .sha256,
            expected
        );
        drop(f);
        assert_eq!(r.memory.used(), 0);
    }
}
