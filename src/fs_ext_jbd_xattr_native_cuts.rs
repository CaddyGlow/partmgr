//! Private lifecycle qualification only: no public mutation admission.
use super::*;
use crate::fs_core::{Budget, Cancellation, NativeName};
use crate::fs_ext::xattr_write;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};
static ARTIFACT_BYTES: AtomicU64 = AtomicU64::new(0);
static WORK_UNITS: AtomicU64 = AtomicU64::new(0);
static ROWS: AtomicU64 = AtomicU64::new(0);
static MAX_BYTES: AtomicU64 = AtomicU64::new(0);
static MAX_WORK: AtomicU64 = AtomicU64::new(0);
static MAX_ROWS: AtomicU64 = AtomicU64::new(0);
static INVENTORY_BYTES: AtomicU64 = AtomicU64::new(0);
static MAX_INVENTORY_BYTES: AtomicU64 = AtomicU64::new(0);
fn debit(counter: &AtomicU64, maximum: &AtomicU64, n: usize, label: &str) {
    let n = u64::try_from(n).unwrap();
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            used.checked_add(n)
                .filter(|next| *next <= maximum.load(Ordering::Relaxed))
        })
        .unwrap_or_else(|_| panic!("explicit xattr qualification {label} budget exhausted"));
}
fn qualification_work(n: usize) {
    debit(&WORK_UNITS, &MAX_WORK, n, "work");
}
fn bounded_write(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) {
    let bytes = bytes.as_ref();
    qualification_work(bytes.len());
    debit(&ARTIFACT_BYTES, &MAX_BYTES, bytes.len(), "artifact");
    fs::write(path, bytes).unwrap();
}
struct Table {
    file: std::io::BufWriter<fs::File>,
}
impl Table {
    fn new(out: &Path, name: &str) -> Self {
        Self {
            file: std::io::BufWriter::with_capacity(
                65536,
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(out.join(name))
                    .unwrap(),
            ),
        }
    }
    fn push_str(&mut self, line: &str) {
        qualification_work(line.len());
        debit(&ROWS, &MAX_ROWS, 1, "rows");
        debit(&ARTIFACT_BYTES, &MAX_BYTES, line.len(), "artifact");
        self.file.write_all(line.as_bytes()).unwrap();
    }
    fn finish(mut self) {
        self.file.flush().unwrap();
        self.file.get_ref().sync_all().unwrap();
    }
}
fn initialize_budgets() {
    for (variable, maximum) in [
        ("PARTMGR_EXT_XATTR_MAX_ARTIFACT_BYTES", &MAX_BYTES),
        ("PARTMGR_EXT_XATTR_MAX_WORK", &MAX_WORK),
        ("PARTMGR_EXT_XATTR_MAX_ROWS", &MAX_ROWS),
        (
            "PARTMGR_EXT_XATTR_MAX_INVENTORY_BYTES",
            &MAX_INVENTORY_BYTES,
        ),
    ] {
        let n: u64 = std::env::var(variable)
            .expect("explicit finite qualification ceiling")
            .parse()
            .unwrap();
        assert!(n > 0);
        maximum.store(n, Ordering::Relaxed);
    }
}

struct Case {
    bs: usize,
    name: &'static str,
    image: &'static str,
    sha: &'static str,
    path: &'static [u8],
    key: &'static [u8],
    operation: &'static str,
    value: &'static [u8],
    outcome: &'static str,
    golden: &'static str,
    golden_sha: &'static str,
}
include!("fs_ext_jbd_xattr_native_cases.rs");
#[derive(Clone, PartialEq, Eq)]
enum Event {
    Write { at: u64, bytes: Vec<u8> },
    Flush,
}
#[derive(Clone, Copy)]
struct Cut {
    event: usize,
    prefix: usize,
    persisted: bool,
    immediate: bool,
}
#[derive(Default)]
struct Probe {
    armed: bool,
    ordinal: usize,
    target: u64,
    bytes: usize,
    fence: bool,
    event_count: usize,
    observations: Vec<(usize, bool, usize)>,
    fail_at: Option<usize>,
    hit: bool,
}
type SharedProbe = std::sync::Arc<std::sync::Mutex<Probe>>;
struct Device {
    live: Vec<u8>,
    durable: Vec<u8>,
    events: Vec<Event>,
    cut: Option<Cut>,
    failed: bool,
    immediate: bool,
    probe: Option<SharedProbe>,
}
impl Device {
    fn new(bytes: Vec<u8>, cut: Option<Cut>) -> Self {
        Self {
            durable: bytes.clone(),
            live: bytes,
            events: Vec::new(),
            cut,
            failed: false,
            immediate: cut.is_some_and(|c| c.immediate),
            probe: None,
        }
    }
    fn crash(self) -> Vec<u8> {
        self.durable
    }
}
impl Storage for Device {
    fn len(&self) -> io::Result<u64> {
        Ok(self.live.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        Source(&self.live).read_exact_at(at, out)?;
        if let Some(probe) = &self.probe {
            let mut probe = probe.lock().unwrap();
            if probe.armed {
                let ordinal = probe.ordinal;
                probe.ordinal += 1;
                if at == probe.target && out.len() == probe.bytes {
                    let fence = probe.fence;
                    let events = probe.event_count;
                    probe.observations.push((ordinal, fence, events));
                }
                if probe.fail_at == Some(ordinal) {
                    assert_eq!(at, probe.target);
                    assert_eq!(out.len(), probe.bytes);
                    let last = out.len() - 1;
                    out[last] ^= 1;
                    probe.hit = true;
                }
            }
        }
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::other("injected stopped device"));
        }
        assert!(!bytes.is_empty());
        if let Some(probe) = &self.probe {
            let mut probe = probe.lock().unwrap();
            probe.event_count = self.events.len() + 1;
            if at <= 1120 && at + bytes.len() as u64 > 1120 && bytes[1120 - at as usize] & 4 != 0 {
                probe.fence = true;
            }
        }
        let index = self.events.len();
        self.events.push(Event::Write {
            at,
            bytes: bytes.to_vec(),
        });
        if let Some(c) = self.cut.filter(|c| c.event == index) {
            assert!(c.prefix <= bytes.len());
            let n = c.prefix;
            self.live[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            if self.immediate {
                self.durable[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            }
            self.failed = true;
            return Err(io::Error::other("injected write cut"));
        }
        self.live[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        if self.immediate {
            self.durable[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("injected stopped device"));
        }
        if let Some(probe) = &self.probe {
            probe.lock().unwrap().event_count = self.events.len() + 1;
        }
        let index = self.events.len();
        self.events.push(Event::Flush);
        if let Some(c) = self.cut.filter(|c| c.event == index) {
            assert_eq!(c.prefix, 0);
            if c.persisted {
                self.durable.clone_from(&self.live);
            }
            self.failed = true;
            return Err(io::Error::other("injected flush cut"));
        }
        self.durable.clone_from(&self.live);
        Ok(())
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn limits() -> LifecycleLimits {
    let planning = xattr_plan::Limits {
        source_bytes: 64 << 20,
        work: 20_000_000_000,
        records: 8,
        affected_bytes: 32 << 10,
        path_depth: 8,
        directory_entries: 10000,
        audit: crate::fs_ext_audit::ExtAuditLimits {
            blocks: 65536,
            inodes: 4096,
            work: 2_000_000_000,
            directory_blocks: 4096,
            directory_entries: 10000,
            findings: 4096,
        },
        encoding: xattr_write::Limits {
            entries: 256,
            value_bytes: 512,
            work: 10_000_000,
        },
    };
    LifecycleLimits {
        proof: xattr_recovery::Limits {
            capsule_bytes: 64 << 10,
            source_bytes: 64 << 20,
            homes: 8,
            journal_blocks: 32768,
            path_depth: 8,
            intent_bytes: 1024,
            work: 60_000_000_000,
            planning,
        },
        records: 8,
        work: 100_000_000_000,
        physical_bytes: 256 << 10,
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(1 << 30),
        cancellation: Cancellation::default(),
    }
}
fn mutation(c: &Case) -> xattr_write::Mutation<'static> {
    match c.operation {
        "replace" => xattr_write::Mutation::Set {
            value: c.value,
            policy: xattr_write::SetPolicy::Replace,
        },
        "create" => xattr_write::Mutation::Set {
            value: c.value,
            policy: xattr_write::SetPolicy::Create,
        },
        "remove" => xattr_write::Mutation::Remove,
        _ => panic!("unknown case"),
    }
}
fn commit_case(c: &Case, device: Device, r: &Resources) -> (io::Result<Outcome>, Device) {
    if MAX_WORK.load(Ordering::Relaxed) > 0 {
        qualification_work(limits().work.checked_mul(4).unwrap());
    }
    let mut s = super::super::super::xattr_session::Session::open_for_recovery(device, limits(), r)
        .unwrap();
    assert_eq!(s.recover(&r.cancellation).unwrap(), Outcome::Noop);
    let path = [NativeName::Bytes(c.path.to_vec())];
    let p = s.plan(&path, c.key, mutation(c), &r.cancellation).unwrap();
    assert!(p.changed);
    let result = s.commit(p, &path, c.key, mutation(c), &r.cancellation);
    (result, s.into_storage())
}
fn recover_device(device: Device, r: &Resources) -> (io::Result<Outcome>, Device) {
    if MAX_WORK.load(Ordering::Relaxed) > 0 {
        qualification_work(limits().work.checked_mul(4).unwrap());
    }
    let mut s = super::super::super::xattr_session::Session::open_for_recovery(device, limits(), r)
        .unwrap();
    let result = s.recover(&r.cancellation);
    (result, s.into_storage())
}
fn equal_homes(a: &[u8], b: &[u8], bs: usize, journal: &[u32]) -> bool {
    a.len() == b.len()
        && a.chunks_exact(bs)
            .zip(b.chunks_exact(bs))
            .enumerate()
            .all(|(i, (a, b))| journal.contains(&(i as u32)) || a == b)
}
fn cut_count(events: &[Event]) -> usize {
    assert!(events.iter().any(|e| matches!(e, Event::Write { .. })));
    assert!(events.iter().any(|e| matches!(e, Event::Flush)));
    events
        .iter()
        .try_fold(0usize, |total, event| {
            let coordinates = match event {
                Event::Write { bytes, .. } => {
                    assert!(!bytes.is_empty());
                    bytes.len().checked_add(1).unwrap().checked_mul(4).unwrap()
                }
                Event::Flush => 4,
            };
            total.checked_add(coordinates)
        })
        .expect("finite exact cut inventory")
}
fn owner_allocation() {
    // Conservative per-entry BTree node + three SHA strings; cumulative debit
    // avoids depending on private allocator/node layout for peak accounting.
    debit(
        &INVENTORY_BYTES,
        &MAX_INVENTORY_BYTES,
        1024,
        "owner inventory",
    );
    qualification_work(1024);
}
fn cuts(events: &[Event]) -> Vec<Cut> {
    assert!(events.iter().any(|e| matches!(e, Event::Write { .. })));
    assert!(events.iter().any(|e| matches!(e, Event::Flush)));
    let count = cut_count(events);
    let bytes = count
        .checked_mul(core::mem::size_of::<Cut>())
        .expect("cut allocation overflow");
    debit(
        &INVENTORY_BYTES,
        &MAX_INVENTORY_BYTES,
        bytes,
        "cut inventory",
    );
    qualification_work(count.checked_add(events.len()).unwrap());
    let mut all = Vec::new();
    all.try_reserve_exact(count)
        .expect("bounded cut allocation");
    assert_eq!(all.capacity(), count, "cut allocation capacity");
    for (event, e) in events.iter().enumerate() {
        let length = match e {
            Event::Write { bytes, .. } => {
                assert!(!bytes.is_empty());
                bytes.len()
            }
            Event::Flush => 0,
        };
        for immediate in [false, true] {
            for persisted in [false, true] {
                for prefix in 0..=length {
                    all.push(Cut {
                        event,
                        prefix,
                        immediate,
                        persisted,
                    });
                }
            }
        }
    }
    all
}
fn image(out: &Path, bytes: &[u8], base: &[u8], bs: usize) -> String {
    qualification_work(bytes.len().checked_mul(4).unwrap());
    assert_eq!(bytes.len(), base.len());
    assert!(bytes.len().is_multiple_of(bs));
    let full = digest(bytes);
    let base_hash = digest(base);
    let name = format!("image-{base_hash}-{full}.json");
    let path = out.join(&name);
    let mut blocks = Vec::new();
    for (index, (current, original)) in bytes
        .chunks_exact(bs)
        .zip(base.chunks_exact(bs))
        .enumerate()
    {
        if current == original {
            continue;
        }
        let hash = digest(current);
        let file = format!("block-{hash}.bin");
        let target = out.join(&file);
        if !target.exists() {
            bounded_write(target, current);
        }
        blocks.push(format!(
            "{{\"block\":{index},\"path\":\"{file}\",\"sha256\":\"{hash}\"}}"
        ));
    }
    let body = format!(
        "{{\"schema\":1,\"base_sha256\":\"{base_hash}\",\"block_bytes\":{bs},\"bytes\":{},\"full_sha256\":\"{full}\",\"blocks\":[{}]}}\n",
        bytes.len(),
        blocks.join(",")
    );
    if path.exists() {
        assert_eq!(fs::read(&path).unwrap(), body.as_bytes());
    } else {
        bounded_write(path, body);
    }
    name
}
fn event_digest(events: &[Event]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"partmgr-xattr-native-event-program-v4");
    for event in events {
        match event {
            Event::Write { at, bytes } => {
                hash.update([1]);
                hash.update(at.to_le_bytes());
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(bytes);
            }
            Event::Flush => hash.update([2]),
        }
    }
    format!("{:x}", hash.finalize())
}
fn trace(out: &Path, name: &str, events: &[Event]) {
    let mut rows = Table::new(out, &format!("{name}-events.tsv"));
    for (i, e) in events.iter().enumerate() {
        match e {
            Event::Write { at, bytes } => {
                let file = format!("{name}-write-{i}.bin");
                bounded_write(out.join(&file), bytes);
                rows.push_str(&format!(
                    "{i}\twrite\t{at}\t{}\t{}\t{file}\n",
                    bytes.len(),
                    digest(bytes)
                ));
            }
            Event::Flush => rows.push_str(&format!("{i}\tflush\t0\t0\t-\t-\n")),
        }
    }
    rows.finish();
}
#[test]
#[ignore = "requires pinned native corpus and fresh evidence directory; private qualification only"]
fn native_private_xattr_cow_all_write_flush_prefix_and_recovery_cuts() {
    let corpus = std::env::var("PARTMGR_EXT_XATTR_CORPUS").expect("native corpus");
    let evidence = std::env::var("PARTMGR_EXT_XATTR_EVIDENCE").expect("fresh evidence");
    let out = Path::new(&evidence);
    fs::create_dir(out).unwrap();
    initialize_budgets();
    let receipt = fs::read(Path::new(&corpus).join("receipt.json")).unwrap();
    assert_eq!(
        digest(&receipt),
        "63d2cc01a2b41ff3dd20f1d57896b8044b565e8f84d584e3eda08b19a7ed8a3c"
    );
    bounded_write(out.join("corpus-receipt.json"), receipt);
    let mut rows = Table::new(out, "cuts.tsv");
    let mut recovery_rows = Table::new(out, "recovery-cuts.tsv");
    let mut controls = Table::new(out, "controls.tsv");
    let mut plans = Table::new(out, "plans.tsv");
    let mut parents = Table::new(out, "recovery-parents.tsv");
    let mut denominators = Table::new(out, "denominators.tsv");
    let mut retries = Table::new(out, "second-retry.tsv");
    let mut adversaries = Table::new(out, "adversaries.tsv");
    let shard_count: usize = std::env::var("PARTMGR_EXT_XATTR_SHARD_COUNT")
        .expect("explicit shard count")
        .parse()
        .unwrap();
    let shard_index: usize = std::env::var("PARTMGR_EXT_XATTR_SHARD_INDEX")
        .expect("explicit shard index")
        .parse()
        .unwrap();
    assert!(shard_count > 0 && shard_index < shard_count);
    for c in CASES {
        let r = resources();
        let source = fs::read(Path::new(&corpus).join(c.image)).unwrap();
        assert_eq!(digest(&source), c.sha);
        image(out, &source, &source, c.bs);
        let native_golden = fs::read(Path::new(&corpus).join(c.golden)).unwrap();
        assert_eq!(digest(&native_golden), c.golden_sha);
        image(out, &native_golden, &source, c.bs);
        if c.outcome != "changed" {
            let mut session = super::super::super::xattr_session::Session::open_for_recovery(
                Device::new(source.clone(), None),
                limits(),
                &r,
            )
            .unwrap();
            assert_eq!(session.recover(&r.cancellation).unwrap(), Outcome::Noop);
            let path = [NativeName::Bytes(c.path.to_vec())];
            let result = session.plan(&path, c.key, mutation(c), &r.cancellation);
            if c.outcome == "refuse" {
                let error = result.err().expect("missing remove must refuse");
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
                assert!(error.to_string().contains("ext user xattr absent"));
            } else {
                let plan = result.unwrap();
                assert!(!plan.changed);
                assert_eq!(
                    session
                        .commit(plan, &path, c.key, mutation(c), &r.cancellation)
                        .unwrap(),
                    Outcome::Noop
                );
            }
            let device = session.into_storage();
            controls.push_str(&format!(
                "{}\t{}\t{}\t{}\t0\t0\t{}\n",
                c.bs,
                c.name,
                c.sha,
                digest(&device.live),
                c.outcome
            ));
            assert!(device.events.is_empty());
            assert_eq!(device.crash(), source);
            assert_eq!(r.memory.used(), 0);
            continue;
        }
        let path = [NativeName::Bytes(c.path.to_vec())];
        let p = xattr_plan::plan(
            &Source(&source),
            71,
            1,
            &path,
            c.key,
            mutation(c),
            limits().proof.planning,
            &r,
        )
        .unwrap();
        let journal = p.journal_blocks().to_vec();
        let affected = p.homes().iter().map(|h| h.block).collect::<Vec<_>>();
        for home in p.homes() {
            plans.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                c.bs,
                c.name,
                home.block,
                digest(&home.original[..c.bs]),
                digest(&home.replacement[..c.bs])
            ));
        }
        // Exercise full native preparation writer+legacy footer+independent parser.
        let capsule =
            xattr_recovery::seal(&p, &path, c.key, mutation(c), limits().proof, &r).unwrap();
        let primary = source[1024..2048].try_into().unwrap();
        let at = journal[0] as usize * c.bs;
        let header = source[at..at + 1024].try_into().unwrap();
        let geometry = clean_geometry(primary, header, journal.len()).unwrap();
        let preparation = prepare_xattr(
            &geometry,
            &p,
            &capsule,
            limits().work,
            limits().physical_bytes,
            &r,
        )
        .unwrap();
        let mut wal = source.clone();
        for block in &preparation.blocks {
            let physical = journal[block.logical as usize] as usize * c.bs;
            wal[physical..physical + c.bs].copy_from_slice(&block.bytes[..c.bs]);
        }
        let parsed = read_xattr_preparation(
            &geometry,
            &journal,
            limits().proof.capsule_bytes,
            limits().work,
            &r,
            |logical, bytes| {
                let at = journal[logical as usize] as usize * c.bs;
                bytes.copy_from_slice(&wal[at..at + bytes.len()]);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(parsed.bytes, capsule.bytes());
        drop((parsed, preparation, capsule, p));
        let (result, baseline) = commit_case(c, Device::new(source.clone(), None), &r);
        assert_eq!(result.unwrap(), Outcome::New);
        let baseline_events = baseline.events.clone();
        let golden = baseline.crash();
        let name = format!("{}-{}", c.bs, c.name);
        bounded_write(out.join(format!("{name}-source.raw")), &source);
        bounded_write(out.join(format!("{name}-new.raw")), &golden);
        trace(out, &name, &baseline_events);
        let mut recovery_owners =
            std::collections::BTreeMap::<String, (usize, String, String)>::new();
        let all_cuts = cuts(&baseline_events);
        assert!(shard_count <= all_cuts.len());
        denominators.push_str(&format!(
            "{name}\t{}\t{}\t{}\t{}\n",
            baseline_events.len(),
            all_cuts.len(),
            shard_index,
            shard_count
        ));
        let mut adversarial_old = false;
        let mut adversarial_new = false;
        for (cut_index, cut) in all_cuts
            .into_iter()
            .enumerate()
            .filter(|(i, _)| i % shard_count == shard_index)
        {
            let (failed, device) = commit_case(c, Device::new(source.clone(), Some(cut)), &r);
            assert!(failed.is_err());
            assert!(device.failed);
            assert!(device.events == baseline_events[..=cut.event]);
            let pre = device.crash();
            let parent = format!("{name}-cut-{cut_index}");
            let pre_file = image(out, &pre, &source, c.bs);
            let (recovered, recovery) = recover_device(Device::new(pre.clone(), None), &r);
            let outcome = recovered.unwrap();
            let recovery_events = recovery.events.clone();
            let after = recovery.crash();
            let old = equal_homes(&after, &source, c.bs, &journal);
            let new = equal_homes(&after, &golden, c.bs, &journal);
            assert_ne!(old, new);
            assert!(match outcome {
                Outcome::Noop => true,
                Outcome::Old => old,
                Outcome::New => new,
            });
            let pre_sha = digest(&pre);
            let owner = if let Some((owner, after_sha, events)) = recovery_owners.get(&pre_sha) {
                assert_eq!(&digest(&after), after_sha);
                assert_eq!(events, &event_digest(&recovery_events));
                *owner
            } else {
                trace(out, &parent, &recovery_events);
                owner_allocation();
                recovery_owners.insert(
                    pre_sha.clone(),
                    (cut_index, digest(&after), event_digest(&recovery_events)),
                );
                cut_index
            };
            parents.push_str(&format!("{name}\t{cut_index}\t{owner}\t{pre_sha}\n"));
            let after_file = image(out, &after, &source, c.bs);
            if !recovery_events.is_empty()
                && !(if old {
                    adversarial_old
                } else {
                    adversarial_new
                })
            {
                let block = (0..source.len() / c.bs)
                    .rev()
                    .find(|b| !journal.contains(&(*b as u32)) && !affected.contains(&(*b as u32)))
                    .unwrap();
                let mut altered = pre.clone();
                altered[block * c.bs + c.bs - 1] ^= 1;
                let (refused, device) = recover_device(Device::new(altered.clone(), None), &r);
                let error = refused.unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("xattr reconstructed original digest"),
                    "{error}"
                );
                assert!(device.events.is_empty());
                assert_eq!(device.live, altered);
                let altered_file = image(out, &altered, &source, c.bs);
                adversaries.push_str(&format!(
                    "{name}\t{cut_index}\t{}\t{}\t{}\t{altered_file}\t{}\t{}\t0\t0\t{}\n",
                    if old { "OLD" } else { "NEW" },
                    digest(&pre),
                    digest(&altered),
                    digest(&device.live),
                    error,
                    digest(&altered)
                ));
                assert_eq!(device.crash(), altered);
                if old {
                    adversarial_old = true;
                } else {
                    adversarial_new = true;
                }
            }
            rows.push_str(&format!(
                "{name}\t{cut_index}\t{}\t{}\t{}\t{}\t{}\t{}\t{:?}\t{pre_file}\t{after_file}\n",
                cut.event,
                cut.prefix,
                cut.persisted,
                cut.immediate,
                digest(&pre),
                digest(&after),
                outcome
            ));
            let (retry, retry_device) = recover_device(Device::new(after.clone(), None), &r);
            assert_eq!(retry.unwrap(), Outcome::Noop);
            assert!(retry_device.events.is_empty());
            retries.push_str(&format!(
                "{name}\t{cut_index}\toperation\t0\t{}\t{}\t0\t0\n",
                digest(&after),
                digest(&retry_device.live)
            ));
            assert_eq!(retry_device.crash(), after);
            if !recovery_events.is_empty() && owner == cut_index {
                for (recovery_index, recut) in cuts(&recovery_events).into_iter().enumerate() {
                    let (failed, recovery) =
                        recover_device(Device::new(pre.clone(), Some(recut)), &r);
                    assert!(failed.is_err());
                    assert!(recovery.failed);
                    assert!(recovery.events == recovery_events[..=recut.event]);
                    let recpre = recovery.crash();
                    let recpre_file = image(out, &recpre, &source, c.bs);
                    let (result, final_device) = recover_device(Device::new(recpre, None), &r);
                    result.unwrap();
                    let final_bytes = final_device.crash();
                    let final_file = image(out, &final_bytes, &source, c.bs);
                    recovery_rows.push_str(&format!("{name}\t{cut_index}\t{recovery_index}\t{}\t{}\t{}\t{}\t{recpre_file}\t{final_file}\n",recut.event,recut.prefix,recut.persisted,recut.immediate));
                    assert_eq!(equal_homes(&final_bytes, &source, c.bs, &journal), old);
                    assert_eq!(equal_homes(&final_bytes, &golden, c.bs, &journal), new);
                    let (retry, retry_device) =
                        recover_device(Device::new(final_bytes.clone(), None), &r);
                    assert_eq!(retry.unwrap(), Outcome::Noop);
                    assert!(retry_device.events.is_empty());
                    retries.push_str(&format!(
                        "{name}\t{cut_index}\trecovery\t{recovery_index}\t{}\t{}\t0\t0\n",
                        digest(&final_bytes),
                        digest(&retry_device.live)
                    ));
                    assert_eq!(retry_device.crash(), final_bytes);
                }
            }
        }
        // Cross-shard verifier requires both active decisions' retained controls.
        // A shard can cover a strict subset of OLD/NEW operation parents.
        let _ = (adversarial_old, adversarial_new);
        assert_eq!(r.memory.used(), 0);
    }
    rows.finish();
    recovery_rows.finish();
    controls.finish();
    plans.finish();
    parents.finish();
    denominators.finish();
    retries.finish();
    adversaries.finish();
}

#[test]
#[ignore = "requires pinned native corpus; actual controller callback regression only"]
fn native_private_xattr_actual_both_source_guard_phases() {
    let corpus = std::env::var("PARTMGR_EXT_XATTR_CORPUS").expect("native corpus");
    for case in CASES.iter().filter(|c| c.name == "shared-replace") {
        let source = fs::read(Path::new(&corpus).join(case.image)).unwrap();
        assert_eq!(digest(&source), case.sha);
        let bs = case.bs;
        let first = u32::from(bs == 1024) as usize;
        let gdt = (first + 1) * bs;
        let table = super::super::super::u32le(&source, gdt + 8) as usize * bs;
        let inodehome = (table + 11 * 128) / bs;
        let root_directory = super::super::super::u32le(&source, table + 128 + 40) as usize;
        let old_ea = super::super::super::u32le(&source, table + 11 * 128 + 104) as usize;
        for block in [inodehome, root_directory, old_ea] {
            let r = resources();
            let probe = std::sync::Arc::new(std::sync::Mutex::new(Probe {
                target: (block * bs) as u64,
                bytes: bs,
                ..Probe::default()
            }));
            let mut device = Device::new(source.clone(), None);
            device.probe = Some(probe.clone());
            let mut session = super::super::super::xattr_session::Session::open_for_recovery(
                device,
                limits(),
                &r,
            )
            .unwrap();
            session.recover(&r.cancellation).unwrap();
            let path = [NativeName::Bytes(case.path.to_vec())];
            let plan = session
                .plan(&path, case.key, mutation(case), &r.cancellation)
                .unwrap();
            let journal = plan.journal_blocks().to_vec();
            probe.lock().unwrap().armed = true;
            assert_eq!(
                session
                    .commit(plan, &path, case.key, mutation(case), &r.cancellation)
                    .unwrap(),
                Outcome::New
            );
            let baseline = session.into_storage();
            let observations = probe.lock().unwrap().observations.clone();
            let phase1 = *observations
                .iter()
                .find(|(_, fence, events)| !*fence && *events == 0)
                .expect("actual phase1 target guard");
            let phase2 = *observations
                .iter()
                .find(|(_, fence, _)| *fence)
                .expect("actual phase2 target guard");
            assert!(phase2.2 > 0);
            for (ordinal, fence, event_count) in [phase1, phase2] {
                let probe = std::sync::Arc::new(std::sync::Mutex::new(Probe {
                    target: (block * bs) as u64,
                    bytes: bs,
                    fail_at: Some(ordinal),
                    ..Probe::default()
                }));
                let mut device = Device::new(source.clone(), None);
                device.probe = Some(probe.clone());
                let mut session = super::super::super::xattr_session::Session::open_for_recovery(
                    device,
                    limits(),
                    &r,
                )
                .unwrap();
                session.recover(&r.cancellation).unwrap();
                let plan = session
                    .plan(&path, case.key, mutation(case), &r.cancellation)
                    .unwrap();
                probe.lock().unwrap().armed = true;
                let error = session
                    .commit(plan, &path, case.key, mutation(case), &r.cancellation)
                    .unwrap_err();
                assert!(error.to_string().contains("changed"));
                assert!(probe.lock().unwrap().hit);
                let after = session.into_storage();
                assert!(after.events == baseline.events[..event_count]);
                if !fence {
                    assert!(after.events.is_empty());
                    assert_eq!(after.live, source);
                } else {
                    for n in 0..source.len() / bs {
                        if n != first && !journal.contains(&(n as u32)) {
                            assert_eq!(
                                &after.live[n * bs..(n + 1) * bs],
                                &source[n * bs..(n + 1) * bs]
                            );
                        }
                    }
                    assert_ne!(after.live[1120] & 4, 0);
                }
                drop(after);
            }
            drop((baseline, probe));
            assert_eq!(r.memory.used(), 0);
        }
    }
}

#[test]
#[ignore = "requires pinned native corpus; resealed typed preparation authority controls"]
fn native_private_xattr_resealed_preparation_controls() {
    let corpus = std::env::var("PARTMGR_EXT_XATTR_CORPUS").expect("native corpus");
    for case in CASES.iter().filter(|case| case.name == "shared-replace") {
        let r = resources();
        let source = fs::read(Path::new(&corpus).join(case.image)).unwrap();
        assert_eq!(digest(&source), case.sha);
        let path = [NativeName::Bytes(case.path.to_vec())];
        let plan = xattr_plan::plan(
            &Source(&source),
            101,
            1,
            &path,
            case.key,
            mutation(case),
            limits().proof.planning,
            &r,
        )
        .unwrap();
        let capsule =
            xattr_recovery::seal(&plan, &path, case.key, mutation(case), limits().proof, &r)
                .unwrap();
        let bs = case.bs;
        let journal = plan.journal_blocks();
        let at = journal[0] as usize * bs;
        let geometry = clean_geometry(
            source[1024..2048].try_into().unwrap(),
            source[at..at + 1024].try_into().unwrap(),
            journal.len(),
        )
        .unwrap();
        let encoded = prepare_xattr(
            &geometry,
            &plan,
            &capsule,
            limits().work,
            limits().physical_bytes,
            &r,
        )
        .unwrap();
        let activate = |blocks: &[LogBlock]| {
            let mut bytes = source.clone();
            for block in blocks {
                let at = journal[block.logical as usize] as usize * bs;
                bytes[at..at + bs].copy_from_slice(&block.bytes[..bs]);
            }
            put32(&mut bytes, journal[0] as usize * bs + 28, geometry.first);
            bytes[1120] |= 4;
            bytes
        };
        let active = activate(&encoded.blocks);
        let (result, after) = recover_device(Device::new(active.clone(), None), &r);
        assert_eq!(result.unwrap(), Outcome::Old);
        assert!(equal_homes(&after.live, &source, bs, journal));
        for variant in 0..3 {
            let mut blocks = encoded
                .blocks
                .iter()
                .map(|block| LogBlock {
                    logical: block.logical,
                    bytes: block.bytes,
                })
                .collect::<Vec<_>>();
            let last = blocks.len() - 1;
            let expected = match variant {
                0 => {
                    put32(&mut blocks[0].bytes, 116, 1);
                    put32(&mut blocks[last].bytes, 116, 1);
                    "xattr native preparation scope"
                }
                1 => {
                    blocks[0].bytes[640 + 60] ^= 1;
                    "xattr reconstructed original digest"
                }
                _ => {
                    let index = plan
                        .homes()
                        .iter()
                        .position(|home| home.block != u32::from(bs == 1024))
                        .unwrap();
                    blocks[1 + index].bytes[bs - 1] ^= 1;
                    "xattr reconstructed original digest"
                }
            };
            // Recompute actual native legacy CRC and SHA framing: these are valid
            // native transactions with forbidden typed authority, not bad checksums.
            legacy::stamp(&geometry, &mut blocks).unwrap();
            let forged = activate(&blocks);
            let (result, device) = recover_device(Device::new(forged.clone(), None), &r);
            let error = result.unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
            assert!(device.events.is_empty());
            assert_eq!(device.live, forged);
        }
        drop((after, encoded, capsule, plan));
        assert_eq!(r.memory.used(), 0);
    }
}

/// Enumerates every operation parent to obtain exact nested denominators before
/// launching exhaustive nested interruption runs. No cut images are published.
#[test]
#[ignore = "bounded resource planning only; source/binary-bound outer required"]
fn native_private_xattr_qualification_resource_plan() {
    let corpus = std::env::var("PARTMGR_EXT_XATTR_CORPUS").unwrap();
    let evidence = std::env::var("PARTMGR_EXT_XATTR_EVIDENCE").unwrap();
    let shard_count: usize = std::env::var("PARTMGR_EXT_XATTR_SHARD_COUNT")
        .unwrap()
        .parse()
        .unwrap();
    assert!(shard_count > 0);
    let out = Path::new(&evidence);
    fs::create_dir(out).unwrap();
    initialize_budgets();
    let receipt = fs::read(Path::new(&corpus).join("receipt.json")).unwrap();
    assert_eq!(
        digest(&receipt),
        "63d2cc01a2b41ff3dd20f1d57896b8044b565e8f84d584e3eda08b19a7ed8a3c"
    );
    bounded_write(out.join("corpus-receipt.json"), receipt);
    let mut parents = Table::new(out, "planning-parents.tsv");
    let mut totals = Table::new(out, "planning-totals.tsv");
    for c in CASES.iter().filter(|case| case.outcome == "changed") {
        let r = resources();
        let source = fs::read(Path::new(&corpus).join(c.image)).unwrap();
        assert_eq!(digest(&source), c.sha);
        let (result, baseline) = commit_case(c, Device::new(source.clone(), None), &r);
        assert_eq!(result.unwrap(), Outcome::New);
        let name = format!("{}-{}", c.bs, c.name);
        let baseline_events = baseline.events.clone();
        let golden = baseline.crash();
        trace(out, &format!("plan-{name}-baseline"), &baseline_events);
        let all_cuts = cuts(&baseline_events);
        assert!(shard_count <= all_cuts.len());
        let mut owners =
            std::collections::BTreeMap::<(usize, String), (usize, String, String)>::new();
        let mut nested_total = 0u128;
        let mut artifact_bound = (source.len() as u128) * 3;
        let mut execution_work = 0u128;
        let mut row_bound = 32u128;
        for (index, cut) in all_cuts.iter().copied().enumerate() {
            let shard = index % shard_count;
            let (failed, device) = commit_case(c, Device::new(source.clone(), Some(cut)), &r);
            assert!(failed.is_err() && device.failed);
            assert!(device.events == baseline_events[..=cut.event]);
            let pre = device.crash();
            let (result, recovery) = recover_device(Device::new(pre.clone(), None), &r);
            result.unwrap();
            let recovery_events = recovery.events.clone();
            let after = recovery.crash();
            let pre_hash = digest(&pre);
            let after_hash = digest(&after);
            let program = event_digest(&recovery_events);
            let key = (shard, pre_hash.clone());
            let (owner, nested) =
                if let Some((owner, expected_after, expected_program)) = owners.get(&key) {
                    assert_eq!(&after_hash, expected_after);
                    assert_eq!(&program, expected_program);
                    (*owner, 0usize)
                } else {
                    owner_allocation();
                    owners.insert(key, (index, after_hash.clone(), program.clone()));
                    trace(out, &format!("plan-{name}-owner-{index}"), &recovery_events);
                    (
                        index,
                        if recovery_events.is_empty() {
                            0
                        } else {
                            cut_count(&recovery_events)
                        },
                    )
                };
            nested_total = nested_total.checked_add(nested as u128).unwrap();
            // All possible nested images differ from source only inside this
            // exact original-parent delta plus the complete recovery write set.
            let mut blocks = std::collections::BTreeSet::new();
            qualification_work(source.len().checked_mul(2).unwrap());
            for (block, (old, current)) in source
                .chunks_exact(c.bs)
                .zip(pre.chunks_exact(c.bs))
                .enumerate()
            {
                if old != current {
                    blocks.insert(block);
                }
            }
            for event in &recovery_events {
                if let Event::Write { at, bytes } = event {
                    assert!(!bytes.is_empty());
                    let start = usize::try_from(*at).unwrap();
                    let end = start.checked_add(bytes.len()).unwrap();
                    assert!(end <= source.len());
                    blocks.extend(start / c.bs..=(end - 1) / c.bs);
                }
            }
            let one_delta = 1024u128 + (blocks.len() as u128 + 1) * (c.bs as u128 + 256);
            let images = 3u128 + (nested as u128) * 3;
            // Includes descriptors, full changed block content without assuming
            // content deduplication, TSVs, traces, and 64KiB native logs per WAL.
            artifact_bound = artifact_bound
                .checked_add(images.checked_mul(one_delta + 65536 + 4096).unwrap())
                .unwrap();
            for event in &recovery_events {
                if let Event::Write { bytes, .. } = event {
                    artifact_bound = artifact_bound
                        .checked_add(bytes.len() as u128 + 1024)
                        .unwrap();
                }
            }
            row_bound = row_bound
                .checked_add(8 + (nested as u128) * 8 + recovery_events.len() as u128)
                .unwrap();
            let invocations = 4u128 + (nested as u128) * 4;
            execution_work = execution_work
                .checked_add(
                    invocations
                        .checked_mul((limits().work as u128) * 4 + (source.len() as u128) * 32)
                        .unwrap(),
                )
                .unwrap();
            parents.push_str(&format!("{name}\t{index}\t{shard}\t{owner}\t{pre_hash}\t{after_hash}\t{program}\t{nested}\t{}\n",blocks.len()));
            // Bind successful baseline and every recovery result in planning
            // metadata without granting an OLD/NEW acceptance shortcut.
            assert_eq!(after.len(), golden.len());
        }
        totals.push_str(&format!("{name}\t{shard_count}\t{}\t{nested_total}\t{artifact_bound}\t{execution_work}\t{row_bound}\t{}\n",all_cuts.len(),digest(&golden)));
        assert_eq!(r.memory.used(), 0);
    }
    parents.finish();
    totals.finish();
}
