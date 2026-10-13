#![cfg(feature = "std")]

use partmgr::io;
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, NativeName, Resources},
    fs_exfat_audit::ExfatAuditLimits,
    fs_exfat_edit::{
        ExfatCreateMetadata, ExfatEditBinding, ExfatEditLimits, ExfatEditRegion, ExfatEditState,
        ExfatEditor,
    },
    fs_exfat_volume::ExfatReadLimits,
    fs_undo::{UndoBinding, UndoLimits, UndoState},
    storage::Storage,
};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
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
        affected_bytes: 32768,
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
fn name(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
fn read(editor: &ExfatEditor<Model, Model>, path: &[NativeName], r: &Resources) -> Vec<u8> {
    let f = editor.open_file(path, r).unwrap();
    let mut b = vec![0; f.len() as usize];
    assert_eq!(editor.read_at(&f, 0, &mut b, r).unwrap(), b.len());
    b
}
#[test]
fn creation_grows_root_and_preserves_exact_native_names_and_initializes_tails() {
    let resources = r();
    let clock = Arc::new(Mutex::new(Clock::default()));
    let mut editor = open(clock, &resources);
    let root = editor.open_directory(&[], &resources).unwrap();
    let mut native = name(&"Long".repeat(20));
    native.push(0xd800);
    let payload = vec![0x49; 700];
    let batch = editor
        .plan_create_file(
            &root,
            &native,
            &ExfatCreateMetadata::epoch_1980(0x20),
            &payload,
            &resources,
        )
        .unwrap();
    let report = batch.namespace_report().unwrap();
    assert_eq!(report.allocated_clusters, 3);
    assert_eq!(report.parent_growth_clusters, 1);
    editor.commit(batch, [1; 16], &resources).unwrap();
    assert!(editor.plan_delete(&root, &native, &resources).is_err());
    drop(root);
    for directory_path in [Vec::new(), path("nested")] {
        let current = editor.open_directory(&directory_path, &resources).unwrap();
        assert_eq!(current.identity().generation, editor.generation());
        assert!(
            current
                .entries()
                .iter()
                .all(|entry| entry.identity().generation == editor.generation()
                    && entry.identity().source == current.identity().source)
        );
    }
    let file = editor
        .open_file(&[NativeName::Utf16(native)], &resources)
        .unwrap();
    assert!(!file.no_fat_chain());
    assert_eq!(file.raw_metadata()[0][8..12], 0x0021_0000_u32.to_le_bytes());
    let mut out = vec![0; 700];
    editor.read_at(&file, 0, &mut out, &resources).unwrap();
    assert_eq!(out, payload);
    drop(file);
    let (target, _, _) = editor.into_stores();
    assert_eq!(&target.bytes[..BASE], &framed()[..BASE]);
    assert_eq!(&target.bytes[BASE + fixture().len()..], &[0x93; 8192]);
    assert!(
        target.bytes[BASE + cluster(12) + 188..BASE + cluster(12) + 512]
            .iter()
            .all(|b| *b == 0)
    );
    assert_eq!(resources.memory.used(), 0);
}
#[test]
fn subdirectory_growth_rename_move_and_empty_deletion_preserve_metadata() {
    let resources = r();
    let mut editor = open(Arc::new(Mutex::new(Clock::default())), &resources);
    let nested = editor.open_directory(&path("nested"), &resources).unwrap();
    let long = name(&"n".repeat(255));
    let batch = editor
        .plan_create_file(
            &nested,
            &long,
            &ExfatCreateMetadata::epoch_1980(0x20),
            b"",
            &resources,
        )
        .unwrap();
    assert_eq!(batch.namespace_report().unwrap().parent_growth_clusters, 1);
    editor.commit(batch, [2; 16], &resources).unwrap();
    drop(nested);
    let root = editor.open_directory(&[], &resources).unwrap();
    let nested_entry = root
        .entries()
        .iter()
        .find(|e| e.name() == name("nested"))
        .unwrap();
    assert_eq!(nested_entry.len(), 1024);
    assert!(!nested_entry.no_fat_chain());
    let nested = editor.open_directory(&path("nested"), &resources).unwrap();
    let batch = editor
        .plan_rename(&nested, &name("inside"), &root, &name("moved"), &resources)
        .unwrap();
    assert!(
        batch
            .namespace_report()
            .unwrap()
            .existing_metadata_preserved
    );
    editor.commit(batch, [3; 16], &resources).unwrap();
    drop(nested);
    drop(root);
    assert_eq!(read(&editor, &path("moved"), &resources), b"child");
    let root = editor.open_directory(&[], &resources).unwrap();
    assert!(
        editor
            .plan_delete(&root, &name("nested"), &resources)
            .is_err()
    );
    let nested = editor.open_directory(&path("nested"), &resources).unwrap();
    assert!(
        editor
            .plan_rename(&root, &name("nested"), &nested, &name("cycle"), &resources)
            .is_err()
    );
    let batch = editor.plan_delete(&nested, &long, &resources).unwrap();
    editor.commit(batch, [4; 16], &resources).unwrap();
    drop(nested);
    drop(root);
    let root = editor.open_directory(&[], &resources).unwrap();
    let batch = editor
        .plan_delete(&root, &name("nested"), &resources)
        .unwrap();
    assert_eq!(batch.namespace_report().unwrap().freed_clusters, 2);
    editor.commit(batch, [5; 16], &resources).unwrap();
    drop(root);
    let root = editor.open_directory(&[], &resources).unwrap();
    let batch = editor
        .plan_create_directory(
            &root,
            &name("empty"),
            &ExfatCreateMetadata::epoch_1980(0x10),
            &resources,
        )
        .unwrap();
    editor.commit(batch, [6; 16], &resources).unwrap();
    drop(root);
    let empty = editor.open_directory(&path("empty"), &resources).unwrap();
    assert!(empty.entries().is_empty());
    drop(empty);
    let root = editor.open_directory(&[], &resources).unwrap();
    let batch = editor
        .plan_delete(&root, &name("empty"), &resources)
        .unwrap();
    editor.commit(batch, [7; 16], &resources).unwrap();
    drop(root);
    drop(editor);
    assert_eq!(resources.memory.used(), 0);
}
#[test]
fn collision_invalid_metadata_names_cancellation_and_budget_do_not_write() {
    let resources = r();
    let editor = open(Arc::new(Mutex::new(Clock::default())), &resources);
    let root = editor.open_directory(&[], &resources).unwrap();
    for native in [
        name("PREFIXNOCHAIN.BIN"),
        name("."),
        name("a/b"),
        vec![97; 256],
    ] {
        assert!(
            editor
                .plan_create_file(
                    &root,
                    &native,
                    &ExfatCreateMetadata::epoch_1980(0x20),
                    b"",
                    &resources
                )
                .is_err()
        );
    }
    let mut metadata = ExfatCreateMetadata::epoch_1980(0x20);
    metadata.raw[25] = 1;
    assert!(
        editor
            .plan_create_file(&root, &name("ok"), &metadata, b"", &resources)
            .is_err()
    );
    let low = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        editor
            .plan_create_file(
                &root,
                &name("ok"),
                &ExfatCreateMetadata::epoch_1980(0x20),
                b"",
                &low
            )
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    resources.cancellation.cancel();
    assert_eq!(
        editor
            .plan_delete(&root, &name("prefixNoChain.bin"), &resources)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    drop(root);
    let (target, journal, _) = editor.into_stores();
    assert_eq!(target.writes, 0);
    assert_eq!(journal.writes, 0);
    assert_eq!(resources.memory.used(), 0);
}
#[test]
fn every_namespace_write_and_barrier_failure_recovers_original_or_committed_bytes() {
    for operation in 0..3 {
        let run = |fail: Option<usize>, retain: bool| {
            let resources = r();
            let clock = Arc::new(Mutex::new(Clock::default()));
            let mut editor = open(clock.clone(), &resources);
            let root = editor.open_directory(&[], &resources).unwrap();
            let nested = editor.open_directory(&path("nested"), &resources).unwrap();
            let long = name(&"abcdefghij".repeat(16));
            let batch = match operation {
                0 => editor.plan_create_file(
                    &root,
                    &long,
                    &ExfatCreateMetadata::epoch_1980(0x20),
                    &[0x62; 700],
                    &resources,
                ),
                1 => editor.plan_rename(
                    &root,
                    &name("prefixNoChain.bin"),
                    &nested,
                    &long,
                    &resources,
                ),
                _ => editor.plan_delete(&root, &name("prefixNoChain.bin"), &resources),
            }
            .unwrap();
            drop(root);
            drop(nested);
            clock.lock().unwrap().fail = fail;
            let result = editor.commit(batch, [11 + operation; 16], &resources);
            let events = clock.lock().unwrap().events;
            clock.lock().unwrap().fail = None;
            if result.as_ref().is_err_and(|e| !e.target_may_have_changed) {
                editor.recover(&resources).unwrap();
            }
            let (mut target, mut journal, state) = editor.into_stores();
            target.crash(retain);
            journal.crash(retain);
            let committed = partmgr::fs_undo::inspect(&journal, &resources)
                .ok()
                .is_some_and(|s| s.state == UndoState::Committed);
            if state == ExfatEditState::NeedsRecovery {
                let editor = ExfatEditor::recover_open(
                    target,
                    journal,
                    ExfatEditRegion {
                        offset: BASE as u64,
                        length: 2 * 1024 * 1024,
                    },
                    UndoBinding {
                        volume: binding().volume,
                        generation: binding().generation,
                        transaction: [11 + operation; 16],
                    },
                    limits(),
                    &resources,
                )
                .unwrap();
                (target, journal, _) = editor.into_stores();
            }
            assert_eq!(resources.memory.used(), 0);
            drop(journal);
            (events, target.bytes, committed)
        };
        let (events, expected, _) = run(None, false);
        for fail in 1..=events {
            for retain in [false, true] {
                let (_, actual, committed) = run(Some(fail), retain);
                assert_eq!(
                    actual,
                    if committed {
                        expected.clone()
                    } else {
                        framed()
                    },
                    "operation {operation} event {fail} retained {retain}"
                );
            }
        }
    }
}
#[test]
#[ignore = "enabled native exFAT namespace gate requires mkfs.exfat/fsck.exfat/TSK and fresh PARTMGR_EXFAT_NAMESPACE_EVIDENCE"]
fn native_exfatprogs_tsk_namespace() {
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        os::unix::fs::FileExt,
        path::PathBuf,
        process::Command,
    };
    let root = PathBuf::from(
        std::env::var_os("PARTMGR_EXFAT_NAMESPACE_EVIDENCE")
            .expect("explicit evidence directory required"),
    );
    std::fs::create_dir(&root).expect("fresh evidence directory required");
    let mut receipt = format!(
        "profile=exclusive-singleFAT-exFAT-create-root-and-subdir-growth-rename-move-delete\neditor_sha256={:x}\ndecoder_sha256={:x}\nmap_sha256={:x}\nfixture_sha256={:x}\nbinary_sha256={:x}\n",
        Sha256::digest(include_bytes!("../src/fs_exfat_edit.rs")),
        Sha256::digest(include_bytes!("../src/fs_exfat_volume.rs")),
        Sha256::digest(include_bytes!("../src/fs_file.rs")),
        Sha256::digest(include_bytes!("fs_exfat_edit_namespace.rs")),
        Sha256::digest(std::fs::read(std::env::current_exe().unwrap()).unwrap())
    );
    receipt.push_str(&format!(
        "boot_sha256={:x}\naudit_sha256={:x}\nundo_sha256={:x}\n",
        Sha256::digest(include_bytes!("../src/fs_exfat.rs")),
        Sha256::digest(include_bytes!("../src/fs_exfat_audit.rs")),
        Sha256::digest(include_bytes!("../src/fs_undo.rs"))
    ));
    receipt.push_str(&format!(
        "namespace_sha256={:x}\n",
        Sha256::digest(include_bytes!("../src/fs_exfat_edit_namespace.rs"))
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
    let bytes = std::fs::read(&native).unwrap();
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
            Ok(self.0.read_exact_at(b, at)?)
        }
        fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
            Ok(self.0.write_at(b, at)?)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(self.0.sync_all()?)
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
    let directory_metadata = ExfatCreateMetadata::epoch_1980(0x10);
    let file_metadata = ExfatCreateMetadata::epoch_1980(0x20);
    for (ordinal, dir) in ["BOX", "EMPTY"].iter().enumerate() {
        let parent = editor.open_directory(&[], &r).unwrap();
        let batch = editor
            .plan_create_directory(&parent, &name(dir), &directory_metadata, &r)
            .unwrap();
        editor.commit(batch, [ordinal as u8 + 1; 16], &r).unwrap();
    }
    let mut expected = std::collections::BTreeMap::new();
    let mut growth = 0;
    for i in 0..32u8 {
        let file_name = format!("native-{i:02}-{}.bin", "abcdefghij".repeat(7));
        let payload: Vec<_> = (0..4097 + usize::from(i) * 7)
            .map(|j| ((j * 31 + usize::from(i)) % 251) as u8)
            .collect();
        let parent = editor.open_directory(&[], &r).unwrap();
        let batch = editor
            .plan_create_file(&parent, &name(&file_name), &file_metadata, &payload, &r)
            .unwrap();
        growth += batch.namespace_report().unwrap().parent_growth_clusters;
        editor.commit(batch, [i + 4; 16], &r).unwrap();
        expected.insert(file_name, payload);
    }
    assert!(
        growth > 0,
        "native root must cross original allocation boundary"
    );
    let first = expected.keys().next().unwrap().clone();
    let source = editor.open_directory(&[], &r).unwrap();
    let dest = editor.open_directory(&path("BOX"), &r).unwrap();
    let batch = editor
        .plan_rename(&source, &name(&first), &dest, &name("moved-Ω.bin"), &r)
        .unwrap();
    editor.commit(batch, [40; 16], &r).unwrap();
    drop(source);
    drop(dest);
    let payload = expected.remove(&first).unwrap();
    expected.insert("BOX/moved-Ω.bin".into(), payload);
    let mut subdirectory_growth = 0;
    for i in 0..20u8 {
        let filename = format!("child-{i:02}-{}.bin", "abcdefghij".repeat(7));
        let payload = vec![i; 517];
        let dest = editor.open_directory(&path("BOX"), &r).unwrap();
        let batch = editor
            .plan_create_file(&dest, &name(&filename), &file_metadata, &payload, &r)
            .unwrap();
        subdirectory_growth += batch.namespace_report().unwrap().parent_growth_clusters;
        editor.commit(batch, [60 + i; 16], &r).unwrap();
        expected.insert(format!("BOX/{filename}"), payload);
    }
    assert!(subdirectory_growth > 0, "native subdirectory must grow");
    let second = expected.keys().find(|n| !n.contains('/')).unwrap().clone();
    let root_dir = editor.open_directory(&[], &r).unwrap();
    let batch = editor
        .plan_rename(
            &root_dir,
            &name(&second),
            &root_dir,
            &name("renamed.bin"),
            &r,
        )
        .unwrap();
    editor.commit(batch, [41; 16], &r).unwrap();
    drop(root_dir);
    let payload = expected.remove(&second).unwrap();
    expected.insert("renamed.bin".into(), payload);
    let deleted = expected
        .keys()
        .find(|n| n.starts_with("native-"))
        .unwrap()
        .clone();
    let root_dir = editor.open_directory(&[], &r).unwrap();
    assert!(editor.plan_delete(&root_dir, &name("BOX"), &r).is_err());
    let batch = editor.plan_delete(&root_dir, &name(&deleted), &r).unwrap();
    editor.commit(batch, [42; 16], &r).unwrap();
    drop(root_dir);
    expected.remove(&deleted);
    let root_dir = editor.open_directory(&[], &r).unwrap();
    let batch = editor.plan_delete(&root_dir, &name("EMPTY"), &r).unwrap();
    editor.commit(batch, [43; 16], &r).unwrap();
    drop(root_dir);
    for directory_path in [Vec::new(), path("BOX")] {
        let directory = editor.open_directory(&directory_path, &r).unwrap();
        assert_eq!(directory.identity().generation, editor.generation());
        assert!(directory.entries().iter().all(|entry| {
            entry.identity().source == directory.identity().source
                && entry.identity().generation == editor.generation()
        }));
    }
    for (p, want) in &expected {
        let path: Vec<_> = p.split('/').map(|s| NativeName::Utf16(name(s))).collect();
        let file = editor.open_file(&path, &r).unwrap();
        let mut got = vec![0; want.len()];
        editor.read_at(&file, 0, &mut got, &r).unwrap();
        assert_eq!(&got, want);
    }
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
    let listing = String::from_utf8(run(
        "fls",
        &["-r", "-p", "-f", "exfat", validation.to_str().unwrap()],
    ))
    .unwrap();
    for (p, want) in &expected {
        let line = listing
            .lines()
            .find(|line| line.split_once('\t').is_some_and(|(_, n)| n == p))
            .unwrap_or_else(|| panic!("missing native path {p}: {listing}"));
        let id = line
            .split_once(':')
            .unwrap()
            .0
            .split_whitespace()
            .last()
            .unwrap();
        let extracted = run("icat", &["-f", "exfat", validation.to_str().unwrap(), id]);
        assert_eq!(&extracted, want);
    }
    assert_eq!(before, Sha256::digest(std::fs::read(&validation).unwrap()));
    assert_eq!(
        framed_before,
        Sha256::digest(std::fs::read(&image).unwrap())
    );
    assert_eq!(
        source_before,
        Sha256::digest(std::fs::read(&native).unwrap())
    );
    receipt.push_str(&format!("resource_limit_bytes=33554432\nplanning_affected_limit_bytes=1048576\nplanning_work_limit=200000\nundo_patch_limit=1024\nundo_body_limit_bytes=4192256\nframing=unchanged\nframed_image_sha256={framed_before:x}\noriginal_mkfs_source_sha256={source_before:x}\nvalidator_image_sha256={before:x}\nroot_growth_clusters={growth}\nsubdirectory_growth_clusters={subdirectory_growth}\nexpected_files=51\neditor_and_TSK_payloads=match\nresource_refund=passed\nstatus=passed\n"));
    std::fs::write(root.join("receipt.txt"), receipt).unwrap();
}
#[test]
fn namespace_rollback_can_restart_after_every_torn_restore_and_barrier() {
    let original = framed();
    let mut saved = None;
    for fail in 1..128 {
        let resources = r();
        let clock = Arc::new(Mutex::new(Clock {
            fail: Some(fail),
            ..Clock::default()
        }));
        let mut editor = open(clock.clone(), &resources);
        let directory = editor.open_directory(&[], &resources).unwrap();
        let batch = editor
            .plan_create_file(
                &directory,
                &name(&"newnamespace".repeat(15)),
                &ExfatCreateMetadata::epoch_1980(0x20),
                &[0x42; 700],
                &resources,
            )
            .unwrap();
        let result = editor.commit(batch, [31; 16], &resources);
        drop(directory);
        let (target, journal, _) = editor.into_stores();
        clock.lock().unwrap().fail = None;
        if result.is_err()
            && target.writes >= 12
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
