#![cfg(feature = "std")]

use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, NativeName, Resources},
    fs_exfat_audit::ExfatAuditLimits,
    fs_exfat_edit::{
        ExfatEditBinding, ExfatEditLimits, ExfatEditRegion, ExfatEditState, ExfatEditor,
    },
    fs_exfat_volume::ExfatReadLimits,
    fs_undo::{UndoBinding, UndoLimits, UndoState},
    storage::Storage,
};
use sha2::{Digest, Sha256};
use std::{
    io,
    sync::{Arc, Mutex},
};
#[derive(Default)]
struct Clock {
    events: usize,
    fail: Option<usize>,
    target_flushes: Vec<(u16, [u8; 32])>,
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
        if self.bytes.len() > BASE + 2 * 1024 * 1024 {
            let flags = u16::from_le_bytes(self.bytes[BASE + 106..BASE + 108].try_into().unwrap());
            self.clock
                .lock()
                .unwrap()
                .target_flushes
                .push((flags, Sha256::digest(&self.bytes).into()));
        }
        Ok(())
    }
}
const SECTOR: usize = 512;
const HEAP: usize = 56 * SECTOR;
fn cluster(n: u32) -> usize {
    HEAP + (n as usize - 2) * SECTOR
}
fn put16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn seal(b: &mut [u8]) {
    for base in [0, 12 * SECTOR] {
        let sum = (0..11 * SECTOR)
            .filter(|i| ![106, 107, 112].contains(i))
            .fold(0_u32, |n, i| {
                (n >> 1 | (n & 1) << 31).wrapping_add(u32::from(b[base + i]))
            });
        for at in (base + 11 * SECTOR..base + 12 * SECTOR).step_by(4) {
            put32(b, at, sum);
        }
    }
}
fn uppercase(unit: u16) -> u16 {
    if (97..=122).contains(&unit) {
        unit - 32
    } else {
        unit
    }
}
fn fix_set(b: &mut [u8], at: usize) {
    let bytes = (usize::from(b[at + 1]) + 1) * 32;
    let sum = (0..bytes)
        .filter(|i| *i != 2 && *i != 3)
        .fold(0_u16, |n, i| {
            (n >> 1 | (n & 1) << 15).wrapping_add(u16::from(b[at + i]))
        });
    put16(b, at + 2, sum);
}
#[allow(clippy::too_many_arguments)] // Independent fixture encodes the on-disk stream fields directly.
fn entry(
    b: &mut [u8],
    slot: usize,
    name: &[u16],
    first: u32,
    length: u64,
    valid: u64,
    contiguous: bool,
    directory: bool,
) -> usize {
    let secondary = 1 + name.len().div_ceil(15);
    b[slot..slot + (secondary + 1) * 32].fill(0);
    b[slot] = 0x85;
    b[slot + 1] = secondary as u8;
    put16(b, slot + 4, if directory { 0x10 } else { 0x20 });
    for at in [8, 12, 16] {
        put32(b, slot + at, 0x0021_0000);
    }
    b[slot + 22..slot + 25].fill(0x80);
    let stream = slot + 32;
    b[stream] = 0xc0;
    b[stream + 1] = if contiguous { 3 } else { 1 };
    b[stream + 3] = name.len() as u8;
    let hash = name
        .iter()
        .flat_map(|u| uppercase(*u).to_le_bytes())
        .fold(0_u16, |n, b| {
            (n >> 1 | (n & 1) << 15).wrapping_add(u16::from(b))
        });
    put16(b, stream + 4, hash);
    put64(b, stream + 8, valid);
    put32(b, stream + 20, first);
    put64(b, stream + 24, length);
    for (i, part) in name.chunks(15).enumerate() {
        let at = slot + (2 + i) * 32;
        b[at] = 0xc1;
        for (j, unit) in part.iter().enumerate() {
            put16(b, at + 2 + j * 2, *unit);
        }
    }
    fix_set(b, slot);
    slot + (secondary + 1) * 32
}
fn fixture() -> Vec<u8> {
    // Independent specification constructor; no production builder/parser creates these bytes.
    let mut b = vec![0; 2 * 1024 * 1024];
    b[..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
    b[3..11].copy_from_slice(b"EXFAT   ");
    put64(&mut b, 72, (2 * 1024 * 1024 / SECTOR) as u64);
    put32(&mut b, 80, 24);
    put32(&mut b, 84, 32);
    put32(&mut b, 88, 56);
    put32(&mut b, 92, 4096 - 56);
    put32(&mut b, 96, 2);
    put32(&mut b, 100, 0x12345678);
    b[105] = 1;
    b[108] = 9;
    b[110] = 1;
    b[112] = 255;
    b[510..512].copy_from_slice(&[0x55, 0xaa]);
    for n in 1..=8 {
        put32(&mut b, (n + 1) * SECTOR - 4, 0xaa550000);
    }
    b.copy_within(..12 * SECTOR, 12 * SECTOR);
    seal(&mut b);
    put32(&mut b, 24 * SECTOR, 0xfffffff8);
    put32(&mut b, 24 * SECTOR + 4, u32::MAX);
    for n in [2, 3, 4, 9] {
        put32(&mut b, 24 * SECTOR + n as usize * 4, u32::MAX);
    }
    put32(&mut b, 24 * SECTOR + 7 * 4, 9);
    for n in [2, 3, 4, 5, 6, 7, 9, 10, 11] {
        let bit = n - 2;
        b[cluster(3) + bit / 8] |= 1 << (bit % 8);
    }
    b[cluster(2)] = 0x81;
    put32(&mut b, cluster(2) + 20, 3);
    put64(&mut b, cluster(2) + 24, 505);
    // Full custom Unicode table using compressed identity runs and mandatory ASCII mappings.
    let mut upcase = vec![0xffff_u16, 97];
    upcase.extend(65..=90);
    upcase.extend([0xffff, 65413]);
    let raw: Vec<_> = upcase.iter().flat_map(|n| n.to_le_bytes()).collect();
    b[cluster(4)..cluster(4) + raw.len()].copy_from_slice(&raw);
    let sum = raw.iter().fold(0_u32, |n, b| {
        (n >> 1 | (n & 1) << 31).wrapping_add(u32::from(*b))
    });
    let at = cluster(2) + 32;
    b[at] = 0x82;
    put32(&mut b, at + 4, sum);
    put32(&mut b, at + 20, 4);
    put64(&mut b, at + 24, raw.len() as u64);
    let at = entry(
        &mut b,
        cluster(2) + 64,
        &"prefixNoChain.bin".encode_utf16().collect::<Vec<_>>(),
        5,
        700,
        600,
        true,
        false,
    );
    let at = entry(&mut b, at, &[0xd800, 88], 7, 900, 900, false, false);
    entry(
        &mut b,
        at,
        &"nested".encode_utf16().collect::<Vec<_>>(),
        10,
        512,
        512,
        true,
        true,
    );
    entry(
        &mut b,
        cluster(10),
        &"inside".encode_utf16().collect::<Vec<_>>(),
        11,
        5,
        5,
        true,
        false,
    );
    for i in 0..1024 {
        b[cluster(5) + i] = ((i * 17 + 3) % 251) as u8;
    } // Tail contains poison, not zeros.
    for i in 0..512 {
        b[cluster(7) + i] = ((i * 13 + 9) % 251) as u8;
        b[cluster(9) + i] = (((i + 512) * 13 + 9) % 251) as u8;
    }
    b[cluster(11)..cluster(11) + 5].copy_from_slice(b"child");
    b
}

const BASE: usize = 4096;
fn r() -> Resources {
    Resources {
        memory: Budget::new(8 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ExfatEditLimits {
    ExfatEditLimits {
        read: ExfatReadLimits {
            max_chain_clusters: 512,
            max_directory_slots: 128,
            max_upcase_bytes: 131072,
        },
        audit: ExfatAuditLimits {
            clusters: 4096,
            entries: 64,
            directory_slots: 1024,
            work: 20000,
            findings: 32,
        },
        affected_bytes: 8192,
        work: 20000,
        undo: UndoLimits {
            patches: 128,
            body_bytes: 131072,
        },
    }
}
fn framed() -> Vec<u8> {
    let mut bytes = vec![0x71; BASE];
    bytes.extend_from_slice(&fixture());
    bytes.extend_from_slice(&[0x93; 8192]);
    bytes
}
fn binding() -> ExfatEditBinding {
    ExfatEditBinding {
        volume: [0x63; 32],
        generation: 7,
    }
}
fn path(name: &str) -> Vec<NativeName> {
    vec![NativeName::Utf16(name.encode_utf16().collect())]
}
fn open(clock: Arc<Mutex<Clock>>, r: &Resources) -> ExfatEditor<Model, Model> {
    ExfatEditor::open(
        Model::new(framed(), clock.clone()),
        Model::new(vec![0; 131072 + 2048], clock),
        ExfatEditRegion {
            offset: BASE as u64,
            length: 2 * 1024 * 1024,
        },
        binding(),
        limits(),
        r,
    )
    .unwrap()
}
#[test]
fn replacement_vdl_and_session_generation() {
    let r = r();
    let clock = Arc::new(Mutex::new(Clock::default()));
    let mut e = open(clock, &r);
    let f = e.open_file(&path("prefixNoChain.bin"), &r).unwrap();
    let raw = f.raw_metadata().to_vec();
    let batch = e.plan_replace(&f, 650, &[0x55; 32], &r).unwrap();
    assert_eq!(batch.dirty_flags(), 2);
    assert!(batch.stage_lengths().len() >= 3);
    assert_eq!(
        e.commit(batch, [1; 16], &r).unwrap().state,
        UndoState::Committed
    );
    assert_eq!(
        e.read_at(&f, 0, &mut [0; 1], &r).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    drop(f);
    let f = e.open_file(&path("prefixNoChain.bin"), &r).unwrap();
    assert_eq!(f.valid_data_length(), 682);
    assert_eq!(
        f.name(),
        "prefixNoChain.bin".encode_utf16().collect::<Vec<_>>()
    );
    assert_eq!(&f.raw_metadata()[0][4..], &raw[0][4..]);
    let mut out = [0xff; 700];
    e.read_at(&f, 0, &mut out, &r).unwrap();
    assert!(out[600..650].iter().all(|b| *b == 0));
    assert_eq!(&out[650..682], &[0x55; 32]);
    assert!(out[682..].iter().all(|b| *b == 0));
    drop(f);
    let (t, _, state) = e.into_stores();
    assert_eq!(state, ExfatEditState::Ready);
    assert_eq!(&t.bytes[..BASE], &[0x71; BASE]);
    assert_eq!(&t.bytes[BASE + 2 * 1024 * 1024..], &[0x93; 8192]);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn grow_convert_chain_truncate_and_empty() {
    let r = r();
    let mut e = open(Arc::new(Mutex::new(Clock::default())), &r);
    let names = path("prefixNoChain.bin");
    for (new_length, transaction) in [(1900, 2), (300, 3), (0, 4), (600, 5)] {
        let f = e.open_file(&names, &r).unwrap();
        let batch = e.plan_resize(&f, new_length, &r).unwrap();
        e.commit(batch, [transaction; 16], &r).unwrap();
        drop(f);
        let file = e.open_file(&names, &r).unwrap();
        assert_eq!(file.len(), new_length);
        assert_eq!(
            file.valid_data_length(),
            new_length.min(if transaction == 3 { 300 } else { new_length })
        );
        if transaction == 2 {
            assert!(!file.no_fat_chain());
            let mut b = vec![0xff; 1900];
            e.read_at(&file, 0, &mut b, &r).unwrap();
            assert!(b[600..].iter().all(|b| *b == 0));
        }
        drop(file);
    }
    drop(e);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn every_torn_write_and_barrier_requires_bound_recovery() {
    for new_length in [1900, 300] {
        let baseline = framed();
        let clock = Arc::new(Mutex::new(Clock::default()));
        let r0 = r();
        let mut e = open(clock.clone(), &r0);
        let f = e.open_file(&path("prefixNoChain.bin"), &r0).unwrap();
        let batch = e.plan_resize(&f, new_length, &r0).unwrap();
        e.commit(batch, [9; 16], &r0).unwrap();
        let events = clock.lock().unwrap().events;
        {
            let trace = &clock.lock().unwrap().target_flushes;
            assert!(
                trace[..trace.len() - 1]
                    .iter()
                    .all(|(flags, _)| flags & 2 != 0)
            );
            assert_eq!(trace.last().unwrap().0, 0);
        }
        drop(f);
        drop(e);
        assert_eq!(r0.memory.used(), 0);
        for fail in 1..=events {
            for retain in [false, true] {
                let r = r();
                let clock = Arc::new(Mutex::new(Clock {
                    events: 0,
                    fail: Some(fail),
                    ..Clock::default()
                }));
                let mut e = open(clock.clone(), &r);
                let f = e.open_file(&path("prefixNoChain.bin"), &r).unwrap();
                let batch = e.plan_resize(&f, new_length, &r).unwrap();
                let result = e.commit(batch, [9; 16], &r);
                assert!(result.is_err(), "fail={fail}");
                assert_eq!(e.state(), ExfatEditState::NeedsRecovery);
                assert!(e.open_file(&path("prefixNoChain.bin"), &r).is_err());
                drop(f);
                clock.lock().unwrap().fail = None;
                if result.as_ref().unwrap_err().target_may_have_changed {
                    let (mut target, mut journal, _) = e.into_stores();
                    target.crash(retain);
                    journal.crash(retain);
                    let status = partmgr::fs_undo::inspect(&journal, &r);
                    if let Ok(status) = status {
                        if status.state == UndoState::Prepared {
                            let e = ExfatEditor::recover_open(
                                target,
                                journal,
                                ExfatEditRegion {
                                    offset: BASE as u64,
                                    length: 2 * 1024 * 1024,
                                },
                                UndoBinding {
                                    volume: binding().volume,
                                    generation: binding().generation,
                                    transaction: [9; 16],
                                },
                                limits(),
                                &r,
                            )
                            .unwrap();
                            let (t, _, _) = e.into_stores();
                            assert_eq!(t.bytes, baseline);
                            assert_eq!(
                                clock.lock().unwrap().target_flushes.last().unwrap().1,
                                Sha256::digest(&baseline).as_slice()
                            );
                        } else if status.state == UndoState::Committed {
                            let e = ExfatEditor::recover_open(
                                target,
                                journal,
                                ExfatEditRegion {
                                    offset: BASE as u64,
                                    length: 2 * 1024 * 1024,
                                },
                                UndoBinding {
                                    volume: binding().volume,
                                    generation: binding().generation,
                                    transaction: [9; 16],
                                },
                                limits(),
                                &r,
                            )
                            .unwrap();
                            drop(e);
                        } else {
                            panic!("target changed with no durable Prepared fail={fail}");
                        }
                    } else {
                        assert!(
                            ExfatEditor::open(
                                target,
                                journal,
                                ExfatEditRegion {
                                    offset: BASE as u64,
                                    length: 2 * 1024 * 1024
                                },
                                binding(),
                                limits(),
                                &r
                            )
                            .is_err()
                        );
                    }
                } else {
                    e.recover(&r).unwrap();
                    let (t, _, _) = e.into_stores();
                    assert_eq!(t.bytes, baseline);
                }
                assert_eq!(r.memory.used(), 0, "fail={fail}");
            }
        }
    }
}
#[test]
fn flagged_dirty_crosslinked_and_budgeted_profiles_fail_before_writes() {
    let r = r();
    for mask in [2u16, 4, 8] {
        let mut b = framed();
        put16(&mut b, BASE + 106, mask);
        let c = Arc::new(Mutex::new(Clock::default()));
        assert!(
            ExfatEditor::open(
                Model::new(b, c.clone()),
                Model::new(vec![0; 140000], c.clone()),
                ExfatEditRegion {
                    offset: BASE as u64,
                    length: 2 * 1024 * 1024
                },
                binding(),
                limits(),
                &r
            )
            .is_err()
        );
        assert_eq!(c.lock().unwrap().events, 0);
    }
    let c = Arc::new(Mutex::new(Clock::default()));
    let mut corrupt = framed();
    let slot = BASE + cluster(2) + 64;
    put32(&mut corrupt, slot + 32 + 20, 7);
    fix_set(&mut corrupt, slot);
    assert!(
        ExfatEditor::open(
            Model::new(corrupt, c.clone()),
            Model::new(vec![0; 140000], c.clone()),
            ExfatEditRegion {
                offset: BASE as u64,
                length: 2 * 1024 * 1024
            },
            binding(),
            limits(),
            &r
        )
        .is_err()
    );
    assert_eq!(c.lock().unwrap().events, 0);
    let c = Arc::new(Mutex::new(Clock::default()));
    let e = open(c.clone(), &r);
    let f = e.open_file(&path("prefixNoChain.bin"), &r).unwrap();
    assert!(e.plan_replace(&f, 699, &[1; 2], &r).is_err());
    let small = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        e.plan_resize(&f, 1900, &small).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    let cancelled = Resources {
        memory: Budget::new(8 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    cancelled.cancellation.cancel();
    assert_eq!(
        e.plan_replace(&f, 0, &[1], &cancelled).err().unwrap().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(c.lock().unwrap().events, 0);
    drop(f);
    drop(e);
    assert_eq!(r.memory.used(), 0);
}

#[test]
#[ignore = "enabled native exFAT editing gate requires mkfs.exfat/fsck.exfat/TSK and fresh PARTMGR_EXFAT_EDIT_EVIDENCE"]
fn native_exfatprogs_tsk_editing() {
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        os::unix::fs::FileExt,
        path::PathBuf,
        process::Command,
    };
    let root = PathBuf::from(
        std::env::var_os("PARTMGR_EXFAT_EDIT_EVIDENCE")
            .expect("explicit evidence directory required"),
    );
    std::fs::create_dir(&root).expect("fresh evidence directory required");
    let mut receipt = format!(
        "profile=exclusive-singleFAT-exFAT-replacement-zeroextension-truncation\neditor_sha256={:x}\ndecoder_sha256={:x}\nmap_sha256={:x}\nfixture_sha256={:x}\nbinary_sha256={:x}\n",
        Sha256::digest(include_bytes!("../src/fs_exfat_edit.rs")),
        Sha256::digest(include_bytes!("../src/fs_exfat_volume.rs")),
        Sha256::digest(include_bytes!("../src/fs_file.rs")),
        Sha256::digest(include_bytes!("fs_exfat_edit.rs")),
        Sha256::digest(std::fs::read(std::env::current_exe().unwrap()).unwrap())
    );
    receipt.push_str(&format!(
        "boot_sha256={:x}\naudit_sha256={:x}\nundo_sha256={:x}\n",
        Sha256::digest(include_bytes!("../src/fs_exfat.rs")),
        Sha256::digest(include_bytes!("../src/fs_exfat_audit.rs")),
        Sha256::digest(include_bytes!("../src/fs_undo.rs"))
    ));
    let mut ordinal = 0;
    let mut run = |tool: &str, args: &[&str]| {
        ordinal += 1;
        let output = Command::new(tool)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("enabled gate missing {tool}: {e}"));
        std::fs::write(
            root.join(format!("{ordinal:03}-{tool}.stdout")),
            &output.stdout,
        )
        .unwrap();
        std::fs::write(
            root.join(format!("{ordinal:03}-{tool}.stderr")),
            &output.stderr,
        )
        .unwrap();
        receipt.push_str(&format!(
            "command={tool} args={args:?} status={} stdout_sha256={:x} stderr_sha256={:x}\n",
            output.status,
            Sha256::digest(&output.stdout),
            Sha256::digest(&output.stderr)
        ));
        assert!(
            output.status.success()
                || args == ["-V"] && matches!(tool, "mkfs.exfat" | "fsck.exfat"),
            "{tool} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    for tool in ["mkfs.exfat", "fsck.exfat", "fls", "icat"] {
        let path = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|dir| dir.join(tool))
            .find(|p| p.is_file())
            .expect("enabled native gate requires tool");
        std::fs::write(
            root.join(format!("tool-{tool}.txt")),
            format!(
                "path={} sha256={:x}\n",
                path.canonicalize().unwrap().display(),
                Sha256::digest(std::fs::read(path).unwrap())
            ),
        )
        .unwrap();
    }
    run("mkfs.exfat", &["-V"]);
    run("fsck.exfat", &["-V"]);
    run("fls", &["-V"]);
    run("icat", &["-V"]);
    run("uname", &["-a"]);
    let native = root.join("mkfs-native.exfat");
    File::create(&native)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    run("mkfs.exfat", &[native.to_str().unwrap()]);
    run("fsck.exfat", &["-n", native.to_str().unwrap()]);
    // Add one scalar-named regular file directly to the independently formatted image.
    // The test writer uses raw little-endian layout and bitmap bits, not the production decoder/editor.
    let mut bytes = std::fs::read(&native).unwrap();
    let sector = 1usize << bytes[108];
    let cluster_size = sector << bytes[109];
    let heap = u32::from_le_bytes(bytes[88..92].try_into().unwrap()) as usize * sector;
    let root_cluster = u32::from_le_bytes(bytes[96..100].try_into().unwrap());
    let root_at = heap + (root_cluster as usize - 2) * cluster_size;
    let count = u32::from_le_bytes(bytes[92..96].try_into().unwrap()) as usize;
    let bitmap_entry = (root_at..root_at + cluster_size)
        .step_by(32)
        .find(|&at| bytes[at] == 0x81)
        .unwrap();
    let bitmap_cluster = u32::from_le_bytes(
        bytes[bitmap_entry + 20..bitmap_entry + 24]
            .try_into()
            .unwrap(),
    );
    let bitmap_at = heap + (bitmap_cluster as usize - 2) * cluster_size;
    let size = 131089usize;
    let need = size.div_ceil(cluster_size);
    let first_index = (0..count - need)
        .find(|&start| {
            (start..start + need).all(|bit| bytes[bitmap_at + bit / 8] & (1 << (bit % 8)) == 0)
        })
        .unwrap();
    let first = (first_index + 2) as u32;
    let file_at = heap + first_index * cluster_size;
    let payload: Vec<_> = (0..size).map(|i| ((i * 31 + 17) % 251) as u8).collect();
    bytes[file_at..file_at + size].copy_from_slice(&payload);
    for bit in first_index..first_index + need {
        bytes[bitmap_at + bit / 8] |= 1 << (bit % 8);
    }
    let slot = (root_at..root_at + cluster_size)
        .step_by(32)
        .find(|&at| bytes[at] == 0)
        .unwrap();
    entry(
        &mut bytes,
        slot,
        &"EDIT.BIN".encode_utf16().collect::<Vec<_>>(),
        first,
        size as u64,
        size as u64,
        true,
        false,
    );
    bytes[112] = 255;
    std::fs::write(&native, &bytes).unwrap();
    run("fsck.exfat", &["-n", native.to_str().unwrap()]);
    let image = root.join("framed.img");
    let mut framed = vec![0x71; BASE];
    framed.extend_from_slice(&bytes);
    framed.extend_from_slice(&[0x93; 8192]);
    std::fs::write(&image, framed).unwrap();
    let journal_path = root.join("external.undo");
    File::create(&journal_path)
        .unwrap()
        .set_len(4 * 1024 * 1024)
        .unwrap();
    struct Host(File);
    impl Storage for Host {
        fn len(&self) -> io::Result<u64> {
            Ok(self.0.metadata()?.len())
        }
        fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
            self.0.read_exact_at(b, at)
        }
        fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
            self.0.write_at(b, at)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.sync_all()
        }
    }
    let r = Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let limits = ExfatEditLimits {
        read: ExfatReadLimits {
            max_chain_clusters: 1024,
            max_directory_slots: 4096,
            max_upcase_bytes: 131072,
        },
        audit: ExfatAuditLimits {
            clusters: 20000,
            entries: 256,
            directory_slots: 16384,
            work: 200000,
            findings: 128,
        },
        affected_bytes: 1024 * 1024,
        work: 200000,
        undo: UndoLimits {
            patches: 1024,
            body_bytes: 4 * 1024 * 1024 - 2048,
        },
    };
    let mut editor = ExfatEditor::open(
        Host(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&image)
                .unwrap(),
        ),
        Host(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&journal_path)
                .unwrap(),
        ),
        ExfatEditRegion {
            offset: BASE as u64,
            length: bytes.len() as u64,
        },
        binding(),
        limits,
        &r,
    )
    .unwrap();
    let file = editor.open_file(&path("EDIT.BIN"), &r).unwrap();
    let batch = editor.plan_replace(&file, 777, &[0x44; 333], &r).unwrap();
    editor.commit(batch, [21; 16], &r).unwrap();
    drop(file);
    let mut expected = payload;
    expected[777..1110].fill(0x44);
    for (new_length, transaction) in [(140000usize, 22), (20000, 23)] {
        let file = editor.open_file(&path("EDIT.BIN"), &r).unwrap();
        let batch = editor.plan_resize(&file, new_length as u64, &r).unwrap();
        editor.commit(batch, [transaction; 16], &r).unwrap();
        drop(file);
        expected.resize(new_length, 0);
    }
    let file = editor.open_file(&path("EDIT.BIN"), &r).unwrap();
    let mut observed = vec![0; expected.len()];
    editor.read_at(&file, 0, &mut observed, &r).unwrap();
    assert_eq!(observed, expected);
    drop(file);
    let (_, _, state) = editor.into_stores();
    assert_eq!(state, ExfatEditState::Ready);
    assert_eq!(r.memory.used(), 0);
    let framed = std::fs::read(&image).unwrap();
    assert_eq!(&framed[..BASE], &[0x71; BASE]);
    assert_eq!(&framed[BASE + bytes.len()..], &[0x93; 8192]);
    let validation = root.join("edited.exfat");
    std::fs::write(&validation, &framed[BASE..BASE + bytes.len()]).unwrap();
    let before = Sha256::digest(std::fs::read(&validation).unwrap());
    let framed_before = Sha256::digest(std::fs::read(&image).unwrap());
    let source_before = Sha256::digest(std::fs::read(&native).unwrap());
    run("fsck.exfat", &["-n", validation.to_str().unwrap()]);
    let listing =
        String::from_utf8(run("fls", &["-f", "exfat", validation.to_str().unwrap()])).unwrap();
    let line = listing
        .lines()
        .find(|line| {
            line.split_once('\t')
                .is_some_and(|(_, name)| name == "EDIT.BIN")
        })
        .unwrap();
    let id = line
        .split_once(':')
        .unwrap()
        .0
        .split_whitespace()
        .last()
        .unwrap();
    let extracted = run("icat", &["-f", "exfat", validation.to_str().unwrap(), id]);
    assert_eq!(extracted, expected);
    assert_eq!(before, Sha256::digest(std::fs::read(&validation).unwrap()));
    assert_eq!(
        framed_before,
        Sha256::digest(std::fs::read(&image).unwrap())
    );
    assert_eq!(
        source_before,
        Sha256::digest(std::fs::read(&native).unwrap())
    );
    drop(run);
    receipt.push_str(&format!("resource_limit_bytes=33554432\nplanning_affected_limit_bytes=1048576\nplanning_work_limit=200000\nundo_patch_limit=1024\nundo_body_limit_bytes=4192256\nframing=unchanged\nframed_image_sha256={framed_before:x}\noriginal_mkfs_source_sha256={source_before:x}\nvalidator_image_sha256={before:x}\nexpected_payload_sha256={:x}\neditor_and_TSK_payloads=match\nresource_refund=passed\nstatus=passed\n",Sha256::digest(expected)));
    std::fs::write(root.join("receipt.txt"), receipt).unwrap();
}

#[test]
fn interrupted_rollback_remains_prepared_and_clean_is_last() {
    let original = framed();
    let mut saved = None;
    for fail in 1..128 {
        let resources = r();
        let clock = Arc::new(Mutex::new(Clock {
            fail: Some(fail),
            ..Clock::default()
        }));
        let mut editor = open(clock.clone(), &resources);
        let file = editor
            .open_file(&path("prefixNoChain.bin"), &resources)
            .unwrap();
        let batch = editor.plan_resize(&file, 1900, &resources).unwrap();
        let result = editor.commit(batch, [31; 16], &resources);
        drop(file);
        let (target, journal, _) = editor.into_stores();
        clock.lock().unwrap().fail = None;
        if result.is_err()
            && target.writes >= 3
            && partmgr::fs_undo::inspect(&journal, &resources)
                .is_ok_and(|s| s.state == UndoState::Prepared)
        {
            saved = Some((target.bytes, target.durable, journal.bytes, journal.durable));
            break;
        }
    }
    let (target_bytes, target_durable, journal_bytes, journal_durable) =
        saved.expect("prepared partially mutated transaction");
    let binding = UndoBinding {
        volume: binding().volume,
        generation: binding().generation,
        transaction: [31; 16],
    };
    let region = ExfatEditRegion {
        offset: BASE as u64,
        length: 2 * 1024 * 1024,
    };
    let mut end = None;
    for fail in 1..128 {
        let resources = r();
        let clock = Arc::new(Mutex::new(Clock {
            fail: Some(fail),
            ..Clock::default()
        }));
        let mut target = Model::new(target_bytes.clone(), clock.clone());
        target.durable.clone_from(&target_durable);
        let mut journal = Model::new(journal_bytes.clone(), clock.clone());
        journal.durable.clone_from(&journal_durable);
        // Borrowed stores retain the modeled crash bytes even if reopen recovery fails.
        struct Borrowed<'a>(&'a mut Model);
        impl Storage for Borrowed<'_> {
            fn len(&self) -> io::Result<u64> {
                self.0.len()
            }
            fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
                self.0.read_exact_at(at, b)
            }
            fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
                self.0.write_at(at, b)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.0.flush()
            }
        }
        let result = ExfatEditor::recover_open(
            Borrowed(&mut target),
            Borrowed(&mut journal),
            region,
            binding,
            limits(),
            &resources,
        );
        if result.is_ok() {
            drop(result);
            end = Some(fail);
            break;
        }
        drop(result);
        for (flags, digest) in &clock.lock().unwrap().target_flushes {
            if flags & 2 == 0 {
                assert_eq!(
                    digest,
                    &<[u8; 32]>::from(Sha256::digest(&original)),
                    "rollback published clean before old data was restored"
                );
            }
        }
        clock.lock().unwrap().fail = None;
        target.crash(true);
        journal.crash(true);
        let status = partmgr::fs_undo::inspect(&journal, &resources).unwrap();
        assert!(matches!(
            status.state,
            UndoState::Prepared | UndoState::RolledBack
        ));
        struct Short(Model);
        impl Storage for Short {
            fn len(&self) -> io::Result<u64> {
                self.0.len()
            }
            fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
                self.0.read_exact_at(at, b)
            }
            fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
                self.0.write_at(at, &b[..b.len().min(7)])
            }
            fn flush(&mut self) -> io::Result<()> {
                self.0.flush()
            }
        }
        let editor = ExfatEditor::recover_open(
            Short(target),
            Short(journal),
            region,
            binding,
            limits(),
            &resources,
        )
        .unwrap();
        let (target, _, _) = editor.into_stores();
        assert_eq!(target.0.bytes, original);
        assert_eq!(resources.memory.used(), 0);
    }
    assert!(
        end.unwrap() > 8,
        "restoration writes and barriers exercised"
    );
}

#[test]
fn exact_surrogate_chained_replacement_preserves_unrelated_bytes() {
    let resources = r();
    let clock = Arc::new(Mutex::new(Clock::default()));
    let mut editor = open(clock, &resources);
    let file = editor
        .open_file(&[NativeName::Utf16(vec![0xd800, 88])], &resources)
        .unwrap();
    assert!(!file.no_fat_chain());
    let batch = editor
        .plan_replace(&file, 480, &[0x24; 64], &resources)
        .unwrap();
    assert!(
        batch
            .patches()
            .iter()
            .any(|p| p.offset() == cluster(7) as u64 + 480)
    );
    assert!(
        batch
            .patches()
            .iter()
            .any(|p| p.offset() == cluster(9) as u64)
    );
    editor.commit(batch, [41; 16], &resources).unwrap();
    drop(file);
    let (target, _, _) = editor.into_stores();
    assert_eq!(
        &target.bytes[BASE + cluster(7) + 480..BASE + cluster(7) + 512],
        &[0x24; 32]
    );
    assert_eq!(
        &target.bytes[BASE + cluster(9)..BASE + cluster(9) + 32],
        &[0x24; 32]
    );
    assert_eq!(
        &target.bytes[BASE + cluster(8)..BASE + cluster(8) + 512],
        &fixture()[cluster(8)..cluster(8) + 512]
    );
    assert_eq!(resources.memory.used(), 0);
}
