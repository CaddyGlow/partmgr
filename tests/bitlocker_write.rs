#![cfg(feature = "bitlocker-write")]
use partmgr::{
    bitlocker::{BitLockerVolume, Limits, MetadataSelection},
    bitlocker_write::{BitLockerSession, Error, SessionOptions, recover_ciphertext},
    fs_core::{Budget, Cancellation, Resources},
    fs_undo::{UndoLimits, UndoState},
    io::{self, ReadAt},
    storage::Storage,
};
use std::sync::{Arc, Mutex};
#[allow(dead_code)]
#[path = "fixtures/bitlocker_vectors.rs"]
mod vectors;
const LENGTH: usize = 1 << 20;
const BOOT: usize = 0x40000;
const OFFSETS: [usize; 3] = [0x50000, 0x60000, 0x70000];
fn w(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn d(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn q(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn crc(b: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &v in b {
        crc ^= u32::from(v);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn fixture(method: u16, size: u16) -> Vec<u8> {
    // Deliberately synthetic metadata with no protectors: diagnostic FVEK only.
    let mut metadata = vec![0; 120];
    metadata[..8].copy_from_slice(b"-FVE-FS-");
    w(&mut metadata, 8, 7);
    w(&mut metadata, 10, 2);
    w(&mut metadata, 12, 4);
    w(&mut metadata, 14, 4);
    q(&mut metadata, 16, LENGTH as u64);
    d(&mut metadata, 28, 1);
    for (i, at) in OFFSETS.iter().enumerate() {
        q(&mut metadata, 32 + 8 * i, *at as u64);
    }
    q(&mut metadata, 56, BOOT as u64);
    d(&mut metadata, 64, 48);
    d(&mut metadata, 68, 1);
    d(&mut metadata, 72, 48);
    d(&mut metadata, 76, 48);
    metadata[80..96].fill(3);
    w(&mut metadata, 100, method);
    w(&mut metadata, 112, 8);
    w(&mut metadata, 114, 1);
    let checksum = crc(&metadata[..112]);
    d(&mut metadata, 116, checksum);
    let mut out = vec![0; LENGTH];
    out[3..11].copy_from_slice(b"-FVE-FS-");
    w(&mut out, 11, size);
    out[160..176].copy_from_slice(&[
        0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 1,
    ]);
    w(&mut out, 510, 0xaa55);
    for (i, at) in OFFSETS.iter().enumerate() {
        q(&mut out, 176 + 8 * i, *at as u64);
        out[*at..*at + 120].copy_from_slice(&metadata);
    }
    let (boot, data) = match (method, size) {
        (0x8004, 512) => (vectors::XTS128_512_BOOT, vectors::XTS128_512_DATA),
        (0x8005, 512) => (vectors::XTS256_512_BOOT, vectors::XTS256_512_DATA),
        (0x8004, 4096) => (vectors::XTS128_4096_BOOT, vectors::XTS128_4096_DATA),
        (0x8005, 4096) => (vectors::XTS256_4096_BOOT, vectors::XTS256_4096_DATA),
        _ => unreachable!(),
    };
    out[BOOT..BOOT + size as usize].copy_from_slice(&hex(boot));
    out[0x2000..0x2000 + size as usize].copy_from_slice(&hex(data));
    out
}
#[derive(Default)]
struct Faults {
    event: usize,
    cut: Option<usize>,
    torn: bool,
    changed_metadata: bool,
}
struct Memory {
    bytes: Vec<u8>,
    faults: Arc<Mutex<Faults>>,
    short: usize,
}
impl Memory {
    fn new(bytes: Vec<u8>, faults: &Arc<Mutex<Faults>>) -> Self {
        Self {
            bytes,
            faults: faults.clone(),
            short: usize::MAX,
        }
    }
}
impl Storage for Memory {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(&self.bytes[at as usize..at as usize + out.len()]);
        if self.faults.lock().unwrap().changed_metadata && OFFSETS.contains(&(at as usize)) {
            out[96] ^= 1;
            if out.len() == 120 {
                let checksum = crc(&out[..112]);
                d(out, 116, checksum);
            }
        }
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        let mut f = self.faults.lock().unwrap();
        let event = f.event;
        f.event += 1;
        if f.cut == Some(event) {
            if f.torn {
                let n = bytes.len() / 2;
                self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            }
            return Err(io::Error::other("injected write cut"));
        }
        let n = bytes.len().min(self.short);
        self.bytes[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut f = self.faults.lock().unwrap();
        let event = f.event;
        f.event += 1;
        if f.cut == Some(event) {
            Err(io::Error::other("injected barrier cut"))
        } else {
            Ok(())
        }
    }
}
struct Image(Vec<u8>);
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(&self.0[at as usize..at as usize + out.len()]);
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(16 << 20),
        cancellation: Cancellation::default(),
    }
}
fn options() -> SessionOptions {
    SessionOptions {
        selection: MetadataSelection::RequireAgreement,
        limits: Limits::default(),
        undo_limits: UndoLimits::default(),
        volume: [1; 32],
        generation: 7,
    }
}
fn open(
    method: u16,
    size: u16,
    faults: &Arc<Mutex<Faults>>,
    r: &Resources,
) -> BitLockerSession<Memory, Memory> {
    BitLockerSession::open_fvek(
        Memory::new(fixture(method, size), faults),
        Memory::new(vec![0; 65536], faults),
        options(),
        &(0..if method == 0x8004 { 32 } else { 64 }).collect::<Vec<_>>(),
        r,
    )
    .unwrap()
}
fn read(bytes: Vec<u8>, method: u16, at: u64, n: usize, r: &Resources) -> Vec<u8> {
    let v = BitLockerVolume::inspect(
        Arc::new(Image(bytes)),
        MetadataSelection::RequireAgreement,
        Limits::default(),
        r,
    )
    .unwrap();
    let unlocked = v
        .unlock_fvek(&(0..if method == 0x8004 { 32 } else { 64 }).collect::<Vec<_>>())
        .unwrap();
    let mut out = vec![0; n];
    unlocked.read_exact_at(at, &mut out).unwrap();
    out
}
#[test]
fn independent_vectors_round_trip_all_xts_profiles_and_relocated_boot() {
    for method in [0x8004, 0x8005] {
        for size in [512, 4096] {
            let r = resources();
            let faults = Arc::default();
            let mut s = open(method, size, &faults, &r);
            let original = fixture(method, size);
            let data: Vec<u8> = (0..size as usize).map(|i| (i * 7 + 3) as u8).collect();
            let p = s.plan_replace(0x2000, &data, [2; 16]).unwrap();
            s.commit(p).unwrap();
            let mut boot = data.clone();
            boot[3..11].copy_from_slice(b"NTFS    ");
            w(&mut boot, 11, size);
            w(&mut boot, 510, 0xaa55);
            let p = s.plan_replace(0, &boot, [3; 16]).unwrap();
            s.commit(p).unwrap();
            let (target, _) = s.into_parts();
            assert_eq!(
                target.bytes, original,
                "encryption must match independent Python vectors"
            );
        }
    }
}
#[test]
fn unaligned_cross_sector_and_boot_replacements_preserve_neighbors() {
    let r = resources();
    let faults = Arc::default();
    let mut s = open(0x8004, 512, &faults, &r);
    let before = read(fixture(0x8004, 512), 0x8004, 0x2000, 1024, &r);
    let payload = vec![0xa9; 37];
    let p = s.plan_replace(0x21f9, &payload, [2; 16]).unwrap();
    s.commit(p).unwrap();
    let p = s.plan_replace(4, b"Boot edit", [3; 16]).unwrap();
    s.commit(p).unwrap();
    let (target, _) = s.into_parts();
    assert_eq!(&target.bytes[..512], &fixture(0x8004, 512)[..512]);
    let actual = read(target.bytes.clone(), 0x8004, 0x2000, 1024, &r);
    let mut expected = before;
    expected[505..542].copy_from_slice(&payload);
    assert_eq!(actual, expected);
    assert_eq!(read(target.bytes, 0x8004, 4, 9, &r), b"Boot edit");
}
#[test]
fn reserved_ranges_bounds_limits_and_stale_session_plans_fail_without_writes() {
    let r = resources();
    let faults = Arc::default();
    let mut s = open(0x8004, 512, &faults, &r);
    for (at, n) in [
        (BOOT as u64, 1),
        (OFFSETS[0] as u64 - 1, 2),
        (LENGTH as u64, 1),
        (u64::MAX, 2),
        (0, 0),
    ] {
        assert!(s.plan_replace(at, &vec![1; n], [2; 16]).is_err());
    }
    let foreign = open(0x8004, 512, &faults, &r)
        .plan_replace(0x2000, b"x", [2; 16])
        .unwrap();
    assert!(matches!(s.commit(foreign), Err(Error::StalePlan)));
    assert_eq!(faults.lock().unwrap().event, 0);
    let stale = s.plan_replace(0x2000, b"x", [2; 16]).unwrap();
    let good = s.plan_replace(0x2000, b"y", [3; 16]).unwrap();
    s.commit(good).unwrap();
    assert!(matches!(s.commit(stale), Err(Error::StalePlan)));
}
#[test]
fn every_mutation_and_barrier_cut_recovers_exact_ciphertext_without_keys() {
    let old = fixture(0x8004, 512);
    let mut committed = None;
    for torn in [false, true] {
        for cut in 0..24 {
            let r = resources();
            let faults = Arc::default();
            let mut s = open(0x8004, 512, &faults, &r);
            let p = s.plan_replace(0x21f9, &[0xa7; 37], [2; 16]).unwrap();
            let binding = p.binding();
            faults.lock().unwrap().cut = Some(cut);
            faults.lock().unwrap().torn = torn;
            let result = s.commit(p);
            let failed = result.is_err();
            if failed {
                assert!(s.recovery_required());
                assert!(matches!(
                    s.plan_replace(0x2000, b"x", [3; 16]),
                    Err(Error::RecoveryRequired)
                ));
            }
            let (mut target, mut journal) = s.into_parts();
            faults.lock().unwrap().cut = None;
            let status = recover_ciphertext(
                &mut target,
                &mut journal,
                binding,
                UndoLimits::default(),
                &r,
            );
            match status {
                Ok(status) if status.state == UndoState::Committed => {
                    if let Some(ref expected) = committed {
                        assert_eq!(&target.bytes, expected);
                    } else {
                        committed = Some(target.bytes.clone());
                    }
                    assert_ne!(target.bytes, old);
                }
                Ok(_) => assert_eq!(target.bytes, old),
                // A torn initial prepared header is deliberately fail-closed. The
                // target is untouched; no authentic rollback authority exists yet.
                Err(_) => {
                    assert!(failed);
                    assert_eq!(target.bytes, old);
                }
            }
        }
    }
    assert!(committed.is_some());
}
#[test]
fn short_target_and_journal_writes_are_completed() {
    let r = resources();
    let faults = Arc::default();
    let mut target = Memory::new(fixture(0x8004, 512), &faults);
    target.short = 17;
    let mut journal = Memory::new(vec![0; 65536], &faults);
    journal.short = 23;
    let mut s =
        BitLockerSession::open_fvek(target, journal, options(), &(0..32).collect::<Vec<_>>(), &r)
            .unwrap();
    let p = s.plan_replace(0x2001, b"short writes", [2; 16]).unwrap();
    s.commit(p).unwrap();
    let (target, _) = s.into_parts();
    assert_eq!(read(target.bytes, 0x8004, 0x2001, 12, &r), b"short writes");
}
#[test]
fn interrupted_cold_rollback_retries_and_rejects_wrong_binding() {
    let r = resources();
    let faults = Arc::default();
    let mut s = open(0x8004, 512, &faults, &r);
    let p = s.plan_replace(0x21f9, &[0xaa; 37], [2; 16]).unwrap();
    let binding = p.binding();
    // Two sector patches: the first target mutation follows undo publication.
    faults.lock().unwrap().cut = Some(11);
    faults.lock().unwrap().torn = true;
    assert!(s.commit(p).is_err());
    let (mut target, mut journal) = s.into_parts();
    faults.lock().unwrap().cut = None;
    let mut wrong = binding;
    wrong.volume[0] ^= 1;
    let saved = target.bytes.clone();
    assert!(
        recover_ciphertext(&mut target, &mut journal, wrong, UndoLimits::default(), &r).is_err()
    );
    assert_eq!(target.bytes, saved);
    let next = faults.lock().unwrap().event;
    faults.lock().unwrap().cut = Some(next + 1);
    assert!(
        recover_ciphertext(
            &mut target,
            &mut journal,
            binding,
            UndoLimits::default(),
            &r
        )
        .is_err()
    );
    faults.lock().unwrap().cut = None;
    assert_eq!(
        recover_ciphertext(
            &mut target,
            &mut journal,
            binding,
            UndoLimits::default(),
            &r
        )
        .unwrap()
        .state,
        UndoState::RolledBack
    );
    assert_eq!(target.bytes, fixture(0x8004, 512));
    assert_eq!(
        recover_ciphertext(
            &mut target,
            &mut journal,
            binding,
            UndoLimits::default(),
            &r
        )
        .unwrap()
        .state,
        UndoState::RolledBack
    );
}
#[test]
fn cancellation_and_planning_budget_fail_without_any_mutation() {
    let r = resources();
    let faults = Arc::default();
    let mut opts = options();
    opts.undo_limits.patches = 1;
    let s = BitLockerSession::open_fvek(
        Memory::new(fixture(0x8004, 512), &faults),
        Memory::new(vec![0; 65536], &faults),
        opts,
        &(0..32).collect::<Vec<_>>(),
        &r,
    )
    .unwrap();
    let baseline = r.memory.used();
    assert!(s.plan_replace(0x21ff, &[1; 2], [2; 16]).is_err());
    assert_eq!(r.memory.used(), baseline);
    r.cancellation.cancel();
    assert!(s.plan_replace(0x2000, &[1], [2; 16]).is_err());
    assert_eq!(faults.lock().unwrap().event, 0);
    drop(s);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn failed_acquisition_returns_owned_stores_for_retry() {
    let r = resources();
    let faults = Arc::default();
    let old = fixture(0x8004, 512);
    let error = match BitLockerSession::open_fvek(
        Memory::new(old.clone(), &faults),
        Memory::new(vec![0; 65536], &faults),
        options(),
        &[],
        &r,
    ) {
        Ok(_) => panic!("invalid key accepted"),
        Err(e) => e,
    };
    assert_eq!(error.storage.bytes, old);
    let session = BitLockerSession::open_fvek(
        error.storage,
        error.journal,
        options(),
        &(0..32).collect::<Vec<_>>(),
        &r,
    )
    .unwrap();
    drop(session);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn changed_metadata_generation_with_same_geometry_rejects_before_journaling() {
    let r = resources();
    let faults = Arc::default();
    let mut session = open(0x8004, 512, &faults, &r);
    let plan = session.plan_replace(0x2000, b"payload", [2; 16]).unwrap();
    // Model a backend violating its exclusivity contract after planning; all
    // three metadata copies retain valid CRCs and unchanged public geometry.
    faults.lock().unwrap().changed_metadata = true;
    assert!(matches!(session.commit(plan), Err(Error::StalePlan)));
    assert_eq!(faults.lock().unwrap().event, 0);
}

#[test]
fn observed_native_extension_reserves_its_complete_logical_region() {
    let r = resources();
    let faults = Arc::default();
    let mut bytes = fixture(0x8004, 512);
    let mut descriptor = vec![0; 100];
    w(&mut descriptor, 0, 100);
    w(&mut descriptor, 2, 15);
    w(&mut descriptor, 4, 15);
    w(&mut descriptor, 6, 1);
    let body = &mut descriptor[8..];
    q(body, 0, BOOT as u64);
    q(body, 8, 512);
    w(body, 16, 5);
    w(body, 18, 76);
    q(body, 24, 0x0a);
    d(body, 44, 512);
    d(body, 48, 4096);
    q(body, 52, 10);
    d(body, 60, 0x6658);
    q(body, 64, 2);
    d(body, 72, 0x0201_0110);
    q(body, 76, 0x90000);
    q(body, 84, 4096);
    for at in OFFSETS {
        let metadata = &mut bytes[at..at + 232];
        metadata[112..].fill(0);
        w(metadata, 8, 14);
        d(metadata, 64, 148);
        d(metadata, 76, 148);
        metadata[112..212].copy_from_slice(&descriptor);
        w(metadata, 224, 8);
        w(metadata, 226, 1);
        let checksum = crc(&metadata[..224]);
        d(metadata, 228, checksum);
    }
    let session = BitLockerSession::open_fvek(
        Memory::new(bytes, &faults),
        Memory::new(vec![0; 65536], &faults),
        options(),
        &(0..32).collect::<Vec<_>>(),
        &r,
    )
    .unwrap();
    for (at, length) in [(0x90000, 1), (0x90fff, 1), (0x8ffff, 2), (0x90fff, 2)] {
        assert!(session.plan_replace(at, &vec![1; length], [2; 16]).is_err());
    }
    assert!(session.plan_replace(0x8ffff, &[1], [2; 16]).is_ok());
    assert!(session.plan_replace(0x91000, &[1], [2; 16]).is_ok());
    assert_eq!(faults.lock().unwrap().event, 0);
}
