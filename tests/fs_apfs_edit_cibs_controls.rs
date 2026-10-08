#![cfg(feature = "std")]

use partmgr::{
    fs_apfs::*, fs_apfs_audit::ApfsAuditLimits, fs_apfs_edit::*, fs_core::*, storage::Storage,
};
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
};
#[allow(dead_code)]
#[path = "fixtures/apfs_cibs.rs"]
mod cibs;
#[allow(dead_code)]
#[path = "fixtures/apfs_clean.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "fixtures/apfs_multichunk.rs"]
mod independent;
const LENGTH: u64 = cibs::LENGTH;
#[derive(Clone)]
struct Sparse {
    blocks: BTreeMap<u64, Vec<u8>>,
    length: u64,
    writes: usize,
    read_calls: u64,
    read_bytes: u64,
    write_bytes: u64,
}
struct Disk(Arc<Mutex<Sparse>>);
fn read(s: &Sparse, at: u64, out: &mut [u8]) -> io::Result<()> {
    if at
        .checked_add(out.len() as u64)
        .is_none_or(|end| end > s.length)
    {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    out.fill(0);
    let mut done = 0;
    while done < out.len() {
        let offset = at + done as u64;
        let n = (4096 - (offset % 4096) as usize).min(out.len() - done);
        if let Some(b) = s.blocks.get(&(offset / 4096)) {
            out[done..done + n]
                .copy_from_slice(&b[offset as usize % 4096..offset as usize % 4096 + n]);
        }
        done += n;
    }
    Ok(())
}
impl Storage for Disk {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().length)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        state.read_calls += 1;
        state.read_bytes += out.len() as u64;
        read(&state, at, out)
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        let mut s = self.0.lock().unwrap();
        if at
            .checked_add(input.len() as u64)
            .is_none_or(|end| end > s.length)
        {
            return Err(io::ErrorKind::WriteZero.into());
        }
        s.writes += 1;
        s.write_bytes += input.len() as u64;
        let mut done = 0;
        while done < input.len() {
            let offset = at + done as u64;
            let n = (4096 - (offset % 4096) as usize).min(input.len() - done);
            let block = offset / 4096;
            if s.blocks.contains_key(&block) || input[done..done + n] != [0; 4096][..n] {
                let b = s.blocks.entry(block).or_insert_with(|| vec![0; 4096]);
                b[offset as usize % 4096..offset as usize % 4096 + n]
                    .copy_from_slice(&input[done..done + n]);
            }
            done += n;
        }
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(32 * 1024 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ApfsEditLimits {
    ApfsEditLimits {
        metadata_blocks: 512,
        attempts: 513,
        work: 16 * 1024 * 1024 * 1024 * 1024,
        read: ApfsReadLimits {
            blocks: LENGTH / 4096,
            checkpoint_blocks: 128,
            objects: 256,
            records: 256,
            work: 1024 * 1024 * 1024,
        },
        audit: ApfsAuditLimits {
            blocks: LENGTH / 4096,
            objects: 512,
            depth: 32,
            work: 1024 * 1024 * 1024,
            findings: 64,
        },
    }
}
fn sparse(bytes: &[u8]) -> Sparse {
    Sparse {
        length: LENGTH,
        writes: 0,
        read_calls: 0,
        read_bytes: 0,
        write_bytes: 0,
        blocks: bytes
            .chunks(4096)
            .enumerate()
            .filter(|(_, b)| b.iter().any(|x| *x != 0))
            .map(|(i, b)| (i as u64, b.to_vec()))
            .collect(),
    }
}
struct Input(ObjectId, u8);
impl FileRead for Input {
    fn identity(&self) -> &ObjectId {
        &self.0
    }
    fn len(&self) -> u64 {
        29
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        let n = (29 - at.min(29)) as usize;
        let n = n.min(out.len()).min(7);
        out[..n].fill(self.1);
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        v(LogicalExtent {
            offset: 0,
            length: 29,
            kind: ExtentKind::Data,
        })
    }
}

#[derive(Clone)]
struct CutControl {
    write_durable: bool,
    failed_flush_durable: bool,
    cut_write: Option<usize>,
    cut_flush: Option<usize>,
    writes: usize,
    flushes: usize,
    trace: Vec<(u64, usize)>,
}
struct CutDisk {
    live: Arc<Mutex<Sparse>>,
    durable: Arc<Mutex<Sparse>>,
    control: Arc<Mutex<CutControl>>,
}
impl Storage for CutDisk {
    fn len(&self) -> io::Result<u64> {
        Ok(self.live.lock().unwrap().length)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        read(&self.live.lock().unwrap(), at, out)
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        let mut c = self.control.lock().unwrap();
        let cut = c.cut_write == Some(c.writes);
        c.writes += 1;
        c.trace.push((at, input.len()));
        let data = if cut {
            &input[..input.len().min(31)]
        } else {
            input
        };
        let n = Disk(self.live.clone()).write_at(at, data)?;
        if c.write_durable {
            Disk(self.durable.clone()).write_at(at, data)?;
        }
        if cut {
            return Err(io::Error::other("modeled torn native publication"));
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut c = self.control.lock().unwrap();
        let cut = c.cut_flush == Some(c.flushes);
        c.flushes += 1;
        if !cut || c.failed_flush_durable {
            *self.durable.lock().unwrap() = self.live.lock().unwrap().clone();
        }
        if cut {
            return Err(io::Error::other("modeled native barrier failure"));
        }
        Ok(())
    }
}
struct Wide(ObjectId);
impl FileRead for Wide {
    fn identity(&self) -> &ObjectId {
        &self.0
    }
    fn len(&self) -> u64 {
        8 * 1024 * 1024
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> Result<usize> {
        r.cancellation.check()?;
        let n = (self.len() - at.min(self.len())).min(out.len() as u64) as usize;
        for (i, byte) in out[..n].iter_mut().enumerate() {
            *byte = ((at + i as u64) % 251) as u8;
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> Result<()>,
    ) -> Result<()> {
        r.cancellation.check()?;
        v(LogicalExtent {
            offset: 0,
            length: self.len(),
            kind: ExtentKind::Data,
        })
    }
}

#[test]
fn checksum_valid_cib_structure_corruptions_refuse_before_writes() {
    let r = resources();
    for mutation in 0..5 {
        let mut bytes = cibs::seed();
        match mutation {
            0 => fixture::p32(&mut bytes, 402 * 4096 + 32, 0),
            1 => fixture::p32(&mut bytes, 402 * 4096 + 36, 2),
            2 => fixture::p64(&mut bytes, 402 * 4096 + 48, 125 * 32768),
            3 => fixture::p64(&mut bytes, 129 * 4096 + 392, 401),
            _ => fixture::p64(&mut bytes, 129 * 4096 + 152, 386),
        }
        for block in [129, 402] {
            fixture::seal(&mut bytes[block * 4096..(block + 1) * 4096]);
        }
        let state = Arc::new(Mutex::new(sparse(&bytes)));
        assert!(
            ApfsEditor::open(Disk(state.clone()), 1026, limits(), &r).is_err(),
            "mutation {mutation}"
        );
        assert_eq!(state.lock().unwrap().writes, 0);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn two_cib_stale_length_and_cancellation_reject_planning_without_writes() {
    for cancellation in [false, true] {
        let r = resources();
        let state = Arc::new(Mutex::new(sparse(&cibs::seed())));
        let editor = ApfsEditor::open(Disk(state.clone()), 1026, limits(), &r).unwrap();
        let id = editor.file_identity(16, &r).unwrap();
        if cancellation {
            r.cancellation.cancel();
        } else {
            state.lock().unwrap().length += 4096;
        }
        assert!(
            editor
                .plan_range(
                    &id,
                    4091,
                    Arc::new(Input(
                        ObjectId {
                            source: 999,
                            generation: 0,
                            native: b"stale two CIB source".to_vec()
                        },
                        0xab
                    )),
                    &r
                )
                .is_err()
        );
        assert_eq!(state.lock().unwrap().writes, 0);
        drop(editor);
        assert_eq!(r.memory.used(), 0);
    }
}
fn cut(
    initial: &Sparse,
    write: Option<usize>,
    flush: Option<usize>,
    write_durable: bool,
    failed_flush_durable: bool,
    crossing: bool,
    r: &Resources,
) -> Vec<(u64, usize)> {
    let live = Arc::new(Mutex::new(initial.clone()));
    let durable = Arc::new(Mutex::new(initial.clone()));
    let control = Arc::new(Mutex::new(CutControl {
        write_durable,
        failed_flush_durable,
        cut_write: write,
        cut_flush: flush,
        writes: 0,
        flushes: 0,
        trace: Vec::new(),
    }));
    let disk = || CutDisk {
        live: live.clone(),
        durable: durable.clone(),
        control: control.clone(),
    };
    let mut editor = ApfsEditor::open(disk(), 1026, limits(), r).unwrap();
    let id = editor.file_identity(16, r).unwrap();
    let source = ObjectId {
        source: 995,
        generation: 0,
        native: b"CIB cold cut model".to_vec(),
    };
    let plan = if crossing {
        editor.plan_replace(&id, Arc::new(Wide(source)), r)
    } else {
        editor.plan_range(&id, 4091, Arc::new(Input(source, 0x95)), r)
    }
    .unwrap();
    let anchor = editor.recovery_anchor();
    let result = editor.commit_range(plan, &anchor, r);
    if write.is_some() || flush.is_some() {
        assert!(result.is_err());
        assert!(editor.file_identity(16, r).is_err());
    } else {
        result.unwrap();
    }
    let trace = control.lock().unwrap().trace.clone();
    drop(editor);
    *live.lock().unwrap() = durable.lock().unwrap().clone();
    {
        let mut control = control.lock().unwrap();
        control.cut_write = None;
        control.cut_flush = None;
    }
    let recovered = ApfsEditor::recover_with_anchor(disk(), &anchor, limits(), r).unwrap();
    let xid = recovered.checkpoint_xid();
    assert!(xid == 1 || xid == 2);
    let expected: Vec<u8> = if xid == 2 && crossing {
        (0..8 * 1024 * 1024u64).map(|p| (p % 251) as u8).collect()
    } else {
        let mut original: Vec<u8> = (0..16397u64)
            .map(|p| {
                if (4096..8192).contains(&p) || (12288..16384).contains(&p) {
                    0
                } else {
                    (p % 4096 * 17 % 251) as u8
                }
            })
            .collect();
        if xid == 2 {
            original[4091..4120].fill(0x95);
        }
        original
    };
    let id = recovered.file_identity(16, r).unwrap();
    let mut actual = vec![0; expected.len()];
    assert_eq!(
        recovered.read_file_at(&id, 0, &mut actual, r).unwrap(),
        actual.len()
    );
    assert_eq!(actual, expected);
    // Every initially allocated metadata/bitmap/data byte survives native COW.
    for (&block, old) in &initial.blocks {
        if block != 0 {
            assert_eq!(live.lock().unwrap().blocks.get(&block), Some(old));
        }
    }
    drop(recovered);
    assert_eq!(r.memory.used(), 0);
    trace
}
#[test]
#[ignore = "large-geometry cut qualification; requires optimized fixed executable"]
fn all_two_cib_metadata_writes_and_barriers_cold_recover_four_models() {
    let dir = std::path::PathBuf::from(
        std::env::var_os("PARTMGR_APFS_CIBS_CUT_EVIDENCE")
            .expect("enabled cuts require fresh evidence directory"),
    );
    assert!(!dir.exists());
    std::fs::create_dir_all(&dir).unwrap();
    let sources: &[(&str, &[u8])] = &[
        (
            "src/fs_apfs_builder.rs",
            include_bytes!("../src/fs_apfs_builder.rs"),
        ),
        (
            "src/fs_apfs_builder_layout.rs",
            include_bytes!("../src/fs_apfs_builder_layout.rs"),
        ),
        (
            "src/fs_apfs_builder_disk.rs",
            include_bytes!("../src/fs_apfs_builder_disk.rs"),
        ),
        (
            "src/fs_apfs_edit.rs",
            include_bytes!("../src/fs_apfs_edit.rs"),
        ),
        (
            "src/fs_apfs_edit_tree.rs",
            include_bytes!("../src/fs_apfs_edit_tree.rs"),
        ),
        (
            "src/fs_apfs_edit_cow.rs",
            include_bytes!("../src/fs_apfs_edit_cow.rs"),
        ),
        (
            "src/fs_apfs_edit_disk.rs",
            include_bytes!("../src/fs_apfs_edit_disk.rs"),
        ),
        (
            "src/fs_apfs_edit_namespace.rs",
            include_bytes!("../src/fs_apfs_edit_namespace.rs"),
        ),
        ("src/fs_apfs.rs", include_bytes!("../src/fs_apfs.rs")),
        (
            "src/fs_apfs_index.rs",
            include_bytes!("../src/fs_apfs_index.rs"),
        ),
        (
            "src/fs_apfs_audit.rs",
            include_bytes!("../src/fs_apfs_audit.rs"),
        ),
        (
            "src/fs_apfs_retention.rs",
            include_bytes!("../src/fs_apfs_retention.rs"),
        ),
        (
            "src/fs_apfs_edit_retention.rs",
            include_bytes!("../src/fs_apfs_edit_retention.rs"),
        ),
        (
            "src/fs_apfs_edit_reclaim.rs",
            include_bytes!("../src/fs_apfs_edit_reclaim.rs"),
        ),
        ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
        ("src/fs_file.rs", include_bytes!("../src/fs_file.rs")),
        ("src/storage.rs", include_bytes!("../src/storage.rs")),
        ("src/lib.rs", include_bytes!("../src/lib.rs")),
        ("Cargo.toml", include_bytes!("../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../Cargo.lock")),
        (
            "tests/fixtures/apfs_clean.rs",
            include_bytes!("fixtures/apfs_clean.rs"),
        ),
        (
            "tests/fixtures/apfs_build_tree.rs",
            include_bytes!("fixtures/apfs_build_tree.rs"),
        ),
        (
            "tests/fixtures/apfs_multichunk.rs",
            include_bytes!("fixtures/apfs_multichunk.rs"),
        ),
        (
            "tests/fs_apfs_edit_multichunk.rs",
            include_bytes!("fs_apfs_edit_multichunk.rs"),
        ),
        (
            "tests/fixtures/apfs_cibs.rs",
            include_bytes!("fixtures/apfs_cibs.rs"),
        ),
        (
            "tests/fs_apfs_edit_cibs.rs",
            include_bytes!("fs_apfs_edit_cibs.rs"),
        ),
        (
            "tests/fs_apfs_edit_cibs_controls.rs",
            include_bytes!("fs_apfs_edit_cibs_controls.rs"),
        ),
    ];

    for &(name, bytes) in sources {
        assert_eq!(std::fs::read(name).unwrap(), bytes);
        let path = dir.join("compiled-sources").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    let executable = std::env::current_exe().unwrap();
    let binary = std::fs::read(&executable).unwrap();
    std::fs::copy(&executable, dir.join("compiled-test-executable")).unwrap();
    let r = resources();
    let initial = sparse(&cibs::crossing_seed());
    let trace = cut(&initial, None, None, true, true, true, &r);
    assert_eq!(trace.len(), 2068);
    let mut cases = 0;
    for writes in [false, true] {
        for flushes in [false, true] {
            // First/last payload writes plus every subsequent bitmap/CIB/root/publication write.
            for at in [0, 2047].into_iter().chain(2048..trace.len()) {
                cut(&initial, Some(at), None, writes, flushes, true, &r);
                cases += 1;
            }
            for barrier in 0..5 {
                cut(&initial, None, Some(barrier), writes, flushes, true, &r);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 108);
    for &(name, bytes) in sources {
        assert_eq!(std::fs::read(name).unwrap(), bytes);
    }
    assert_eq!(std::fs::read(&executable).unwrap(), binary);
    std::fs::write(dir.join("receipt.json"), "{\"status\":\"passed\",\"cases\":108,\"models\":4,\"barriers\":5,\"selected_payload_writes\":2,\"all_metadata_writes\":true}\n").unwrap();
    println!(
        "two-CIB cuts={cases} writes={} barriers=5 models=4",
        trace.len()
    );
}

struct SeedFaultDisk {
    disk: Disk,
    flushes: usize,
    mode: u8,
    cancellation: Cancellation,
}
impl Storage for SeedFaultDisk {
    fn len(&self) -> io::Result<u64> {
        self.disk.len()
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        if self.flushes == 4 && at == 0 {
            match self.mode {
                0 => return Err(io::Error::other("injected indexed seed I/O")),
                1 => {
                    self.disk.read_exact_at(at, out)?;
                    out[100] ^= 1;
                    return Ok(());
                }
                _ => self.cancellation.cancel(),
            }
        }
        self.disk.read_exact_at(at, out)
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        self.disk.write_at(at, input)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        self.disk.flush()
    }
}
#[test]
fn indexed_seed_io_changed_bytes_and_cancellation_require_recovery() {
    for mode in 0..3 {
        let r = resources();
        let state = Arc::new(Mutex::new(sparse(&cibs::seed())));
        let mut editor = ApfsEditor::open(
            SeedFaultDisk {
                disk: Disk(state.clone()),
                flushes: 0,
                mode,
                cancellation: r.cancellation.clone(),
            },
            1026,
            limits(),
            &r,
        )
        .unwrap();
        let id = editor.file_identity(16, &r).unwrap();
        let plan = editor
            .plan_range(
                &id,
                4091,
                Arc::new(Input(
                    ObjectId {
                        source: 994,
                        generation: 0,
                        native: b"seed fault".to_vec(),
                    },
                    0x96,
                )),
                &r,
            )
            .unwrap();
        let anchor = editor.recovery_anchor();
        let error = editor.commit_range(plan, &anchor, &r).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InterruptedWrite);
        assert!(editor.file_identity(16, &r).is_err());
        drop(editor);
        assert_eq!(r.memory.used(), 0);
        let fresh = resources();
        let recovered =
            ApfsEditor::recover_with_anchor(Disk(state), &anchor, limits(), &fresh).unwrap();
        assert_eq!(recovered.checkpoint_xid(), 2);
        drop(recovered);
        assert_eq!(fresh.memory.used(), 0);
    }
}
