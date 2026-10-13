//! Explicit disposable-buffer native owned-journal cut evidence only.
use super::*;
use crate::{
    fs_core::{
        Budget, Cancellation, ExtentKind, FileRead, LogicalExtent, NativeName, ObjectId, Resources,
    },
    fs_ext_audit::ExtAuditLimits,
    storage::Storage,
};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    fmt::Write,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
};
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn required(n: &str) -> PathBuf {
    let p = PathBuf::from(std::env::var_os(n).expect(n));
    assert!(p.is_absolute());
    p
}
fn checked(p: &Path, h: &str) -> Vec<u8> {
    let b = fs::read(p).unwrap();
    assert_eq!(hash(&b), h, "{}", p.display());
    b
}
fn resources() -> Resources {
    Resources {
        // Namespace planning retains two bounded directory inventories alongside
        // the planner and the projected ownership audit.
        memory: Budget::new(256 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> session::Limits {
    session::Limits {
        audit: ExtAuditLimits {
            blocks: 65536,
            inodes: 16384,
            work: 64_000_000,
            directory_blocks: 65536,
            directory_entries: 65536,
            findings: 1024,
        },
        file_blocks: 65536,
        affected_blocks: 256,
        affected_bytes: 4 << 20,
    }
}
fn planning() -> crate::fs_ext_edit::ExtEditLimits {
    crate::fs_ext_edit::ExtEditLimits {
        audit: limits().audit,
        file_blocks: 65536,
        directory_entries: 65536,
        affected_bytes: 4 << 20,
        // Planner reserves 64 bytes per work unit, independently of audit work.
        work: 1_000_000,
        undo: crate::fs_undo::UndoLimits {
            patches: 4096,
            body_bytes: 16 << 20,
        },
    }
}
struct Input {
    bytes: Vec<u8>,
    id: ObjectId,
}
impl FileRead for Input {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> crate::fs_core::Result<usize> {
        r.cancellation.check()?;
        let at = at as usize;
        let n = out.len().min(37).min(self.bytes.len().saturating_sub(at));
        if n > 0 {
            out[..n].copy_from_slice(&self.bytes[at..at + n]);
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        v: &mut dyn FnMut(LogicalExtent) -> crate::fs_core::Result<()>,
    ) -> crate::fs_core::Result<()> {
        r.cancellation.check()?;
        v(LogicalExtent {
            offset: 0,
            length: self.len(),
            kind: ExtentKind::Data,
        })
    }
}
#[derive(Clone, Copy, Debug)]
enum Event {
    Write(usize),
    Flush,
}
struct Model {
    snapshot: Option<Rc<RefCell<Vec<u8>>>>,
    visible: Vec<u8>,
    durable: Vec<u8>,
    trace: Vec<Event>,
    cut: usize,
    prefix: usize,
    immediate: bool,
    persist: bool,
    hit: bool,
}
impl Model {
    fn new(bytes: &[u8]) -> Self {
        Self {
            snapshot: None,
            visible: bytes.to_vec(),
            durable: bytes.to_vec(),
            trace: Vec::new(),
            cut: usize::MAX,
            prefix: 0,
            immediate: false,
            persist: false,
            hit: false,
        }
    }
}
impl Storage for Model {
    fn len(&self) -> io::Result<u64> {
        Ok(self.visible.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        out.copy_from_slice(
            self.visible
                .get(at as usize..at as usize + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.trace.push(Event::Write(bytes.len()));
        let fail = self.trace.len() == self.cut;
        let n = if fail {
            self.prefix.min(bytes.len())
        } else {
            bytes.len()
        };
        self.visible[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
        if self.immediate {
            self.durable[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
        }
        if fail {
            self.hit = true;
            Err(io::Error::other("owned native cut write"))
        } else {
            Ok(n)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.trace.push(Event::Flush);
        let fail = self.trace.len() == self.cut;
        if let Some(snapshot) = &self.snapshot {
            snapshot.borrow_mut().clone_from(&self.visible);
        }
        if !fail || self.persist {
            self.durable.clone_from(&self.visible);
        }
        if fail {
            self.hit = true;
            Err(io::Error::other("owned native cut flush"))
        } else {
            Ok(())
        }
    }
}
fn names(name: &[u8]) -> [NativeName; 1] {
    [NativeName::Bytes(name.to_vec())]
}
fn contents(s: &session::Session<Model>, name: &[u8], expected: &[u8], r: &Resources) {
    let file = s.file_at(&names(name), &r.cancellation).unwrap();
    let mut actual = vec![0; expected.len()];
    let mut at = 0;
    while at < actual.len() {
        let n = s
            .read_at(&file, at as u64, &mut actual[at..], &r.cancellation)
            .unwrap();
        assert!(n > 0);
        at += n;
    }
    let mut eof = [0];
    assert_eq!(
        s.read_at(&file, at as u64, &mut eof, &r.cancellation)
            .unwrap(),
        0
    );
    assert_eq!(actual, expected);
}
fn saved(out: &Path, b: &[u8]) -> (String, String) {
    let h = hash(b);
    let relative = format!("images/{h}.raw");
    let p = out.join(&relative);
    if p.exists() {
        assert_eq!(fs::read(p).unwrap(), b);
    } else {
        fs::write(p, b).unwrap();
    }
    (h, relative)
}
fn home_equal(a: &[u8], b: &[u8], bs: usize, journal: &[u32]) -> bool {
    a.len() == b.len()
        && a.chunks(bs)
            .zip(b.chunks(bs))
            .enumerate()
            .all(|(i, (a, b))| journal.contains(&(i as u32)) || a == b)
}
#[test]
#[ignore = "requires pinned e2fsprogs owned-journal corpus and fresh evidence directory"]
fn native_owned_ext3_allocation_cuts() {
    let corpus = required("PARTMGR_EXT_OWNED_CORPUS");
    let root = required("PARTMGR_GATE_SOURCE_ROOT");
    let out = required("PARTMGR_EXT_OWNED_EVIDENCE");
    fs::create_dir(&out).unwrap();
    fs::create_dir(out.join("images")).unwrap();
    let receipt = checked(
        &corpus.join("receipt.json"),
        "1fc841600d01124b9de21d56d9fea357dc89a0f56d5f01db108fc7cd955705cf",
    );
    fs::write(out.join("fixture-receipt.json"), receipt).unwrap();
    let models = checked(
        &corpus.join("models.tsv"),
        "4d5197032c6b09f8a36d65a8db2760dd1f66c2dac9d529cfd48b7fd74ad90598",
    );
    let sources = compiled_sources();
    let snapshot = || {
        let mut manifest = String::new();
        for (name, b) in sources {
            assert_eq!(fs::read(root.join(name)).unwrap(), *b);
            writeln!(manifest, "{}  {name}", hash(b)).unwrap();
        }
        manifest
    };
    let before = snapshot();
    fs::write(out.join("source-start.sha256"), &before).unwrap();
    for (name, b) in sources {
        let p = out.join("compiled-source").join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b).unwrap();
    }
    let binary = fs::read(std::env::current_exe().unwrap()).unwrap();
    fs::write(out.join("gate-binary"), &binary).unwrap();
    let mut manifest = String::from(
        "bs\tcase\tevent\tmodel\tfault_kind\tprefix\tpre_sha256\tpre_path\tretried_sha256\tretried_path\tresult\n",
    );
    let mut counts = String::new();
    let mut errors = String::new();
    let mut total = 0;
    for line in std::str::from_utf8(&models).unwrap().lines() {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 12);
        let bs: usize = f[0].parse().unwrap();
        let original = checked(&corpus.join(f[1]), f[2]);
        let payload = checked(&corpus.join(f[3]), f[4]);
        let append = Input {
            bytes: checked(&corpus.join(f[5]), f[6]),
            id: ObjectId {
                source: 71,
                generation: 1,
                native: vec![1],
            },
        };
        let expected = checked(&corpus.join(f[7]), f[8]);
        let unrelated = checked(&corpus.join(f[9]), f[10]);
        assert_eq!(
            [payload.as_slice(), append.bytes.as_slice()].concat(),
            expected
        );
        let r = resources();
        let bootstrap =
            bootstrap::Bootstrap::read(&Model::new(&original), 65536, 32_000_000, &r).unwrap();
        let mut journal = bootstrap.physical_blocks.clone();
        journal.extend_from_slice(&bootstrap.metadata_blocks);
        journal.sort_unstable();
        journal.dedup();
        drop(bootstrap);
        let mapping = journal.iter().map(|v| format!("{v}\n")).collect::<String>();
        fs::write(out.join(format!("journal-map-b{bs}.tsv")), mapping).unwrap();
        let mut baseline = session::Session::open(Model::new(&original), limits(), &r).unwrap();
        let file = baseline
            .file_at(&names(b"payload"), &r.cancellation)
            .unwrap();
        baseline
            .operate(
                session::Operation::Extend {
                    file: &file,
                    input: &append,
                },
                planning(),
                &r.cancellation,
            )
            .unwrap();
        drop(file);
        contents(&baseline, b"payload", &expected, &r);
        contents(&baseline, b"unrelated", &unrelated, &r);
        let (after, state) = baseline.into_storage();
        assert_eq!(state, session::State::Ready);
        let trace = after.trace.clone();
        let mut events = String::from("event\tkind\tbytes\n");
        for (index, event) in trace.iter().enumerate() {
            match event {
                Event::Write(n) => writeln!(events, "{}\twrite\t{n}", index + 1).unwrap(),
                Event::Flush => writeln!(events, "{}\tflush\t0", index + 1).unwrap(),
            }
        }
        fs::write(out.join(format!("events-b{bs}.tsv")), events).unwrap();
        let grown = after.visible;
        let (_, baseline_path) = saved(&out, &grown);
        writeln!(
            counts,
            "bs={bs} events={} baseline={baseline_path}",
            trace.len()
        )
        .unwrap();
        assert_eq!(r.memory.used(), 0);
        // Repeated owned operations on the same native image, separately archived.
        let snapshot = Rc::new(RefCell::new(grown.clone()));
        let mut repeat_model = Model::new(&grown);
        repeat_model.snapshot = Some(snapshot.clone());
        let mut repeat = session::Session::open(repeat_model, limits(), &r).unwrap();
        let mut step_expected = expected.clone();
        step_expected[..b"owned-repeated".len()].copy_from_slice(b"owned-repeated");
        let extended_expected_path = format!("repeat-b{bs}-extended-payload.bin");
        fs::write(out.join(&extended_expected_path), &step_expected).unwrap();
        let truncated_expected_path = format!("repeat-b{bs}-truncated-payload.bin");
        fs::write(
            out.join(&truncated_expected_path),
            &step_expected[..payload.len()],
        )
        .unwrap();
        let temporary_path = format!("repeat-b{bs}-temporary.bin");
        fs::write(out.join(&temporary_path), b"temporary-owned").unwrap();
        let mut steps = String::from(
            "step\timage_sha256\timage_path\tmain_name\tmain_payload_path\ttemporary_payload_path\n",
        );
        let mut save_step = |step: &str, name: &str, main: &str, temporary: &str| {
            let (h, p) = saved(&out, &snapshot.borrow());
            writeln!(steps, "{step}\t{h}\t{p}\t{name}\t{main}\t{temporary}").unwrap();
        };
        let file = repeat.file_at(&names(b"payload"), &r.cancellation).unwrap();
        repeat
            .replace(&file, 0, b"owned-repeated", &r.cancellation)
            .unwrap();
        drop(file);
        save_step("replace", "payload", &extended_expected_path, "-");
        repeat
            .operate(
                session::Operation::Rename {
                    source: &[],
                    name: b"payload",
                    destination: &[],
                    new_name: b"renamed",
                },
                planning(),
                &r.cancellation,
            )
            .unwrap();
        save_step("rename", "renamed", &extended_expected_path, "-");
        let file = repeat.file_at(&names(b"renamed"), &r.cancellation).unwrap();
        repeat
            .operate(
                session::Operation::Truncate {
                    file: &file,
                    length: payload.len() as u64,
                },
                planning(),
                &r.cancellation,
            )
            .unwrap();
        drop(file);
        save_step("truncate", "renamed", &truncated_expected_path, "-");
        let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100644);
        repeat
            .operate(
                session::Operation::CreateFile {
                    parent: &[],
                    name: b"temporary",
                    metadata: &metadata,
                    payload: b"temporary-owned",
                },
                planning(),
                &r.cancellation,
            )
            .unwrap();
        save_step(
            "create",
            "renamed",
            &truncated_expected_path,
            &temporary_path,
        );
        repeat
            .operate(
                session::Operation::Delete {
                    parent: &[],
                    name: b"temporary",
                    deletion_time: 946684800,
                },
                planning(),
                &r.cancellation,
            )
            .unwrap();
        save_step("delete", "renamed", &truncated_expected_path, "-");
        fs::write(out.join(format!("repeat-steps-b{bs}.tsv")), steps).unwrap();
        contents(&repeat, b"unrelated", &unrelated, &r);
        let (repeated, _) = repeat.into_storage();
        let (_, path) = saved(&out, &repeated.visible);
        writeln!(
            counts,
            "bs={bs} repeated={path} operations=extend,replace,rename,truncate,create,delete"
        )
        .unwrap();
        let mut case = 0;
        for (event, kind) in trace.iter().enumerate() {
            let prefixes = match kind {
                Event::Write(n) => vec![0, n / 2, *n],
                Event::Flush => vec![0],
            };
            for immediate in [false, true] {
                for persist in [false, true] {
                    for prefix in &prefixes {
                        case += 1;
                        total += 1;
                        let r = resources();
                        let mut storage = Model::new(&original);
                        storage.trace.clear();
                        storage.cut = event + 1;
                        storage.prefix = *prefix;
                        storage.immediate = immediate;
                        storage.persist = persist;
                        let mut s = session::Session::open(storage, limits(), &r).unwrap();
                        let file = s.file_at(&names(b"payload"), &r.cancellation).unwrap();
                        let result = s.operate(
                            session::Operation::Extend {
                                file: &file,
                                input: &append,
                            },
                            planning(),
                            &r.cancellation,
                        );
                        drop(file);
                        let error = result.expect_err("cut must fail");
                        writeln!(
                            errors,
                            "bs={bs} case={case} event={} cause={error:?}",
                            event + 1
                        )
                        .unwrap();
                        let (mut cut, _) = s.into_storage();
                        assert!(cut.hit);
                        let (prehash, prepath) = saved(&out, &cut.durable);
                        cut.visible.clone_from(&cut.durable);
                        cut.cut = usize::MAX;
                        cut.trace.clear();
                        let mut retry =
                            session::Session::open_for_recovery(cut, limits(), &r).unwrap();
                        retry.recover(&r.cancellation).unwrap();
                        let file = retry.file_at(&names(b"payload"), &r.cancellation).unwrap();
                        drop(file);
                        let (recovered, state) = retry.into_storage();
                        assert_eq!(state, session::State::Ready);
                        let result = if home_equal(&recovered.visible, &original, bs, &journal) {
                            "old"
                        } else {
                            assert!(home_equal(&recovered.visible, &grown, bs, &journal));
                            "new"
                        };
                        let retry_s =
                            session::Session::open(Model::new(&recovered.visible), limits(), &r)
                                .unwrap();
                        contents(
                            &retry_s,
                            b"payload",
                            if result == "old" { &payload } else { &expected },
                            &r,
                        );
                        contents(&retry_s, b"unrelated", &unrelated, &r);
                        drop(retry_s);
                        let (retryhash, retrypath) = saved(&out, &recovered.visible);
                        writeln!(manifest,"{bs}\t{case}\t{}\t{}\t{}\t{prefix}\t{prehash}\t{prepath}\t{retryhash}\t{retrypath}\t{result}",event+1,if immediate{"immediate"}else{"volatile"},match kind{Event::Write(_)=>"write",Event::Flush=>if persist{"flush-persist"}else{"flush-none"}}).unwrap();
                        assert_eq!(r.memory.used(), 0);
                    }
                }
            }
        }
        assert_eq!(hash(&fs::read(corpus.join(f[1])).unwrap()), f[2]);
    }
    assert_eq!(snapshot(), before);
    fs::write(out.join("source-end.sha256"), snapshot()).unwrap();
    fs::write(out.join("cuts.tsv"), manifest).unwrap();
    fs::write(out.join("observations.txt"), counts).unwrap();
    fs::write(out.join("cut-errors.txt"), errors).unwrap();
    checked(
        &corpus.join("receipt.json"),
        "1fc841600d01124b9de21d56d9fea357dc89a0f56d5f01db108fc7cd955705cf",
    );
    checked(
        &corpus.join("models.tsv"),
        "4d5197032c6b09f8a36d65a8db2760dd1f66c2dac9d529cfd48b7fd74ad90598",
    );
    fs::write(out.join("report.txt"),format!("complete=true\ncases={total}\nscope=private owned ext3 allocation and simulated cut cold recovery; native verifier required; no kernel dirty or public qualification\n")).unwrap();
}

fn compiled_sources() -> &'static [(&'static str, &'static [u8])] {
    &[
        ("src/bitlocker.rs", include_bytes!("../src/bitlocker.rs")),
        (
            "src/bitlocker_crypto.rs",
            include_bytes!("../src/bitlocker_crypto.rs"),
        ),
        (
            "src/bitlocker_disk.rs",
            include_bytes!("../src/bitlocker_disk.rs"),
        ),
        (
            "src/bitlocker_swtpm.rs",
            include_bytes!("../src/bitlocker_swtpm.rs"),
        ),
        (
            "src/bitlocker_tpm.rs",
            include_bytes!("../src/bitlocker_tpm.rs"),
        ),
        (
            "src/bitlocker_tpm_host.rs",
            include_bytes!("../src/bitlocker_tpm_host.rs"),
        ),
        (
            "src/bitlocker_write.rs",
            include_bytes!("../src/bitlocker_write.rs"),
        ),
        ("src/codec.rs", include_bytes!("../src/codec.rs")),
        ("src/conversion.rs", include_bytes!("../src/conversion.rs")),
        ("src/editor.rs", include_bytes!("../src/editor.rs")),
        ("src/error.rs", include_bytes!("../src/error.rs")),
        ("src/extended.rs", include_bytes!("../src/extended.rs")),
        ("src/fs_apfs.rs", include_bytes!("../src/fs_apfs.rs")),
        (
            "src/fs_apfs_audit.rs",
            include_bytes!("../src/fs_apfs_audit.rs"),
        ),
        (
            "src/fs_apfs_builder.rs",
            include_bytes!("../src/fs_apfs_builder.rs"),
        ),
        (
            "src/fs_apfs_builder_disk.rs",
            include_bytes!("../src/fs_apfs_builder_disk.rs"),
        ),
        (
            "src/fs_apfs_builder_layout.rs",
            include_bytes!("../src/fs_apfs_builder_layout.rs"),
        ),
        (
            "src/fs_apfs_disk.rs",
            include_bytes!("../src/fs_apfs_disk.rs"),
        ),
        (
            "src/fs_apfs_edit.rs",
            include_bytes!("../src/fs_apfs_edit.rs"),
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
        (
            "src/fs_apfs_edit_reclaim.rs",
            include_bytes!("../src/fs_apfs_edit_reclaim.rs"),
        ),
        (
            "src/fs_apfs_edit_retention.rs",
            include_bytes!("../src/fs_apfs_edit_retention.rs"),
        ),
        (
            "src/fs_apfs_edit_tree.rs",
            include_bytes!("../src/fs_apfs_edit_tree.rs"),
        ),
        (
            "src/fs_apfs_index.rs",
            include_bytes!("../src/fs_apfs_index.rs"),
        ),
        (
            "src/fs_apfs_retention.rs",
            include_bytes!("../src/fs_apfs_retention.rs"),
        ),
        (
            "src/fs_apfs_tree.rs",
            include_bytes!("../src/fs_apfs_tree.rs"),
        ),
        (
            "src/fs_build_io.rs",
            include_bytes!("../src/fs_build_io.rs"),
        ),
        ("src/fs_copy.rs", include_bytes!("../src/fs_copy.rs")),
        ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
        (
            "src/fs_discovery.rs",
            include_bytes!("../src/fs_discovery.rs"),
        ),
        ("src/fs_exfat.rs", include_bytes!("../src/fs_exfat.rs")),
        (
            "src/fs_exfat_audit.rs",
            include_bytes!("../src/fs_exfat_audit.rs"),
        ),
        (
            "src/fs_exfat_builder.rs",
            include_bytes!("../src/fs_exfat_builder.rs"),
        ),
        (
            "src/fs_exfat_copy.rs",
            include_bytes!("../src/fs_exfat_copy.rs"),
        ),
        (
            "src/fs_exfat_edit.rs",
            include_bytes!("../src/fs_exfat_edit.rs"),
        ),
        (
            "src/fs_exfat_edit_namespace.rs",
            include_bytes!("../src/fs_exfat_edit_namespace.rs"),
        ),
        (
            "src/fs_exfat_tree.rs",
            include_bytes!("../src/fs_exfat_tree.rs"),
        ),
        (
            "src/fs_exfat_volume.rs",
            include_bytes!("../src/fs_exfat_volume.rs"),
        ),
        ("src/fs_ext.rs", include_bytes!("../src/fs_ext.rs")),
        (
            "src/fs_ext_audit.rs",
            include_bytes!("../src/fs_ext_audit.rs"),
        ),
        (
            "src/fs_ext_builder.rs",
            include_bytes!("../src/fs_ext_builder.rs"),
        ),
        (
            "src/fs_ext_checksum.rs",
            include_bytes!("../src/fs_ext_checksum.rs"),
        ),
        (
            "src/fs_ext_copy.rs",
            include_bytes!("../src/fs_ext_copy.rs"),
        ),
        (
            "src/fs_ext_directory.rs",
            include_bytes!("../src/fs_ext_directory.rs"),
        ),
        (
            "src/fs_ext_edit.rs",
            include_bytes!("../src/fs_ext_edit.rs"),
        ),
        (
            "src/fs_ext_edit_allocation.rs",
            include_bytes!("../src/fs_ext_edit_allocation.rs"),
        ),
        (
            "src/fs_ext_edit_geometry.rs",
            include_bytes!("../src/fs_ext_edit_geometry.rs"),
        ),
        (
            "src/fs_ext_edit_namespace.rs",
            include_bytes!("../src/fs_ext_edit_namespace.rs"),
        ),
        (
            "src/fs_ext_edit_ordered_tests.rs",
            include_bytes!("../src/fs_ext_edit_ordered_tests.rs"),
        ),
        (
            "src/fs_ext_jbd_ordered_tests.rs",
            include_bytes!("../src/fs_ext_jbd_ordered_tests.rs"),
        ),
        (
            "src/fs_ext_edit_transaction.rs",
            include_bytes!("../src/fs_ext_edit_transaction.rs"),
        ),
        (
            "src/fs_ext_extent.rs",
            include_bytes!("../src/fs_ext_extent.rs"),
        ),
        (
            "src/fs_ext_hash.rs",
            include_bytes!("../src/fs_ext_hash.rs"),
        ),
        (
            "src/fs_ext_integrity.rs",
            include_bytes!("../src/fs_ext_integrity.rs"),
        ),
        ("src/fs_ext_jbd.rs", include_bytes!("../src/fs_ext_jbd.rs")),
        (
            "src/fs_ext_jbd_header_last_tests.rs",
            include_bytes!("../src/fs_ext_jbd_header_last_tests.rs"),
        ),
        (
            "src/fs_ext_jbd_bootstrap.rs",
            include_bytes!("../src/fs_ext_jbd_bootstrap.rs"),
        ),
        (
            "src/fs_ext_jbd_foreign.rs",
            include_bytes!("../src/fs_ext_jbd_foreign.rs"),
        ),
        (
            "src/fs_ext_jbd_foreign_native.rs",
            include_bytes!("../src/fs_ext_jbd_foreign_native.rs"),
        ),
        (
            "src/fs_ext_jbd_foreign_native_cuts.rs",
            include_bytes!("../src/fs_ext_jbd_foreign_native_cuts.rs"),
        ),
        (
            "src/fs_ext_jbd_foreign_recover.rs",
            include_bytes!("../src/fs_ext_jbd_foreign_recover.rs"),
        ),
        (
            "src/fs_ext_jbd_foreign_recover_tests.rs",
            include_bytes!("../src/fs_ext_jbd_foreign_recover_tests.rs"),
        ),
        (
            "src/fs_ext_jbd_legacy.rs",
            include_bytes!("../src/fs_ext_jbd_legacy.rs"),
        ),
        (
            "src/fs_ext_jbd_modern_extent.rs",
            include_bytes!("../src/fs_ext_jbd_modern_extent.rs"),
        ),
        (
            "src/fs_ext_jbd_modern_htree.rs",
            include_bytes!("../src/fs_ext_jbd_modern_htree.rs"),
        ),
        (
            "src/fs_ext_jbd_modern_indirect.rs",
            include_bytes!("../src/fs_ext_jbd_modern_indirect.rs"),
        ),
        (
            "src/fs_ext_jbd_modern_indirect_tests.rs",
            include_bytes!("../src/fs_ext_jbd_modern_indirect_tests.rs"),
        ),
        (
            "src/fs_ext_jbd_modern_inode.rs",
            include_bytes!("../src/fs_ext_jbd_modern_inode.rs"),
        ),
        (
            "src/fs_ext_jbd_modern_namespace.rs",
            include_bytes!("../src/fs_ext_jbd_modern_namespace.rs"),
        ),
        (
            "src/fs_ext_jbd_modern_namespace_tests.rs",
            include_bytes!("../src/fs_ext_jbd_modern_namespace_tests.rs"),
        ),
        (
            "src/fs_ext_jbd_modern_plan.rs",
            include_bytes!("../src/fs_ext_jbd_modern_plan.rs"),
        ),
        (
            "src/fs_ext_jbd_modern_tests.rs",
            include_bytes!("../src/fs_ext_jbd_modern_tests.rs"),
        ),
        (
            "src/fs_ext_jbd_native.rs",
            include_bytes!("../src/fs_ext_jbd_native.rs"),
        ),
        (
            "src/fs_ext_jbd_native_indirect.rs",
            include_bytes!("../src/fs_ext_jbd_native_indirect.rs"),
        ),
        (
            "src/fs_ext_jbd_native_inode.rs",
            include_bytes!("../src/fs_ext_jbd_native_inode.rs"),
        ),
        (
            "src/fs_ext_jbd_native_legacy.rs",
            include_bytes!("../src/fs_ext_jbd_native_legacy.rs"),
        ),
        (
            "src/fs_ext_jbd_native_namespace.rs",
            include_bytes!("../src/fs_ext_jbd_native_namespace.rs"),
        ),
        (
            "src/fs_ext_jbd_overlay.rs",
            include_bytes!("../src/fs_ext_jbd_overlay.rs"),
        ),
        (
            "src/fs_ext_jbd_owned_native_cuts.rs",
            include_bytes!("../src/fs_ext_jbd_owned_native_cuts.rs"),
        ),
        (
            "src/fs_ext_jbd_recovery.rs",
            include_bytes!("../src/fs_ext_jbd_recovery.rs"),
        ),
        (
            "src/fs_ext_jbd_session.rs",
            include_bytes!("../src/fs_ext_jbd_session.rs"),
        ),
        (
            "src/fs_ext_owned.rs",
            include_bytes!("../src/fs_ext_owned.rs"),
        ),
        (
            "tests/fs_ext_owned.rs",
            include_bytes!("../tests/fs_ext_owned.rs"),
        ),
        (
            "src/fs_ext_jbd_transaction.rs",
            include_bytes!("../src/fs_ext_jbd_transaction.rs"),
        ),
        (
            "src/fs_ext_journal.rs",
            include_bytes!("../src/fs_ext_journal.rs"),
        ),
        (
            "src/fs_ext_metadata.rs",
            include_bytes!("../src/fs_ext_metadata.rs"),
        ),
        (
            "src/fs_ext_modern.rs",
            include_bytes!("../src/fs_ext_modern.rs"),
        ),
        (
            "src/fs_ext_resize.rs",
            include_bytes!("../src/fs_ext_resize.rs"),
        ),
        (
            "src/fs_ext_tree.rs",
            include_bytes!("../src/fs_ext_tree.rs"),
        ),
        (
            "src/fs_ext_acl_semantics.rs",
            include_bytes!("fs_ext_acl_semantics.rs"),
        ),
        (
            "src/fs_ntfs_logfile/native_analysis_context/target_query.rs",
            include_bytes!("fs_ntfs_logfile/native_analysis_context/target_query.rs"),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/target_intents.rs",
            include_bytes!(
                "fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/target_intents.rs"
            ),
        ),
        (
            "src/fs_ext_jbd_xattr.rs",
            include_bytes!("fs_ext_jbd_xattr.rs"),
        ),
        (
            "src/fs_ext_xattr_plan.rs",
            include_bytes!("fs_ext_xattr_plan.rs"),
        ),
        (
            "src/fs_ext_xattr_recovery.rs",
            include_bytes!("fs_ext_xattr_recovery.rs"),
        ),
        (
            "src/fs_ext_xattr_session.rs",
            include_bytes!("fs_ext_xattr_session.rs"),
        ),
        (
            "src/fs_ext_xattr_write.rs",
            include_bytes!("fs_ext_xattr_write.rs"),
        ),
        (
            "src/fs_ntfs_native_log_target.rs",
            include_bytes!("fs_ntfs_native_log_target.rs"),
        ),
        (
            "src/fs_ntfs_logfile/native_analysis_context/target_query/target_runs.rs",
            include_bytes!("fs_ntfs_logfile/native_analysis_context/target_query/target_runs.rs"),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/target_intents/native_dirty_runs.rs",
            include_bytes!(
                "fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/target_intents/native_dirty_runs.rs"
            ),
        ),
        (
            "src/fs_ext_jbd_xattr_native_cuts.rs",
            include_bytes!("fs_ext_jbd_xattr_native_cuts.rs"),
        ),
        (
            "src/fs_ext_jbd_xattr_native_cases.rs",
            include_bytes!("fs_ext_jbd_xattr_native_cases.rs"),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/target_intents/native_dirty_runs/redo_analysis.rs",
            include_bytes!(
                "fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/target_intents/native_dirty_runs/redo_analysis.rs"
            ),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/target_intents/native_dirty_runs/redo_analysis/native_file.rs",
            include_bytes!(
                "fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/target_intents/native_dirty_runs/redo_analysis/native_file.rs"
            ),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/target_intents/native_dirty_runs/redo_analysis/undo_analysis.rs",
            include_bytes!(
                "fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/target_intents/native_dirty_runs/redo_analysis/undo_analysis.rs"
            ),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/target_intents/native_dirty_runs/redo_analysis/undo_analysis/mirror_finalization.rs",
            include_bytes!(
                "fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/target_intents/native_dirty_runs/redo_analysis/undo_analysis/mirror_finalization.rs"
            ),
        ),
        ("src/fs_ext_acl.rs", include_bytes!("../src/fs_ext_acl.rs")),
        (
            "src/fs_ext_xattr.rs",
            include_bytes!("../src/fs_ext_xattr.rs"),
        ),
        ("src/fs_fat.rs", include_bytes!("../src/fs_fat.rs")),
        (
            "src/fs_fat_audit.rs",
            include_bytes!("../src/fs_fat_audit.rs"),
        ),
        (
            "src/fs_fat_builder.rs",
            include_bytes!("../src/fs_fat_builder.rs"),
        ),
        (
            "src/fs_fat_edit.rs",
            include_bytes!("../src/fs_fat_edit.rs"),
        ),
        (
            "src/fs_fat_edit_namespace.rs",
            include_bytes!("../src/fs_fat_edit_namespace.rs"),
        ),
        (
            "src/fs_fat_edit_resize.rs",
            include_bytes!("../src/fs_fat_edit_resize.rs"),
        ),
        (
            "src/fs_fat_tree.rs",
            include_bytes!("../src/fs_fat_tree.rs"),
        ),
        ("src/fs_file.rs", include_bytes!("../src/fs_file.rs")),
        ("src/fs_flash.rs", include_bytes!("../src/fs_flash.rs")),
        ("src/fs_hfs.rs", include_bytes!("../src/fs_hfs.rs")),
        (
            "src/fs_hfs_audit.rs",
            include_bytes!("../src/fs_hfs_audit.rs"),
        ),
        (
            "src/fs_hfs_tree.rs",
            include_bytes!("../src/fs_hfs_tree.rs"),
        ),
        ("src/fs_hfsplus.rs", include_bytes!("../src/fs_hfsplus.rs")),
        (
            "src/fs_hfsplus_allocation_builder.rs",
            include_bytes!("../src/fs_hfsplus_allocation_builder.rs"),
        ),
        (
            "src/fs_hfsplus_audit.rs",
            include_bytes!("../src/fs_hfsplus_audit.rs"),
        ),
        (
            "src/fs_hfsplus_builder.rs",
            include_bytes!("../src/fs_hfsplus_builder.rs"),
        ),
        (
            "src/fs_hfsplus_builder_inventory.rs",
            include_bytes!("../src/fs_hfsplus_builder_inventory.rs"),
        ),
        (
            "src/fs_hfsplus_builder_layout.rs",
            include_bytes!("../src/fs_hfsplus_builder_layout.rs"),
        ),
        (
            "src/fs_hfsplus_edit.rs",
            include_bytes!("../src/fs_hfsplus_edit.rs"),
        ),
        (
            "src/fs_hfsplus_fork_builder.rs",
            include_bytes!("../src/fs_hfsplus_fork_builder.rs"),
        ),
        (
            "src/fs_hfsplus_metadata_builder.rs",
            include_bytes!("../src/fs_hfsplus_metadata_builder.rs"),
        ),
        (
            "src/fs_hfsplus_node.rs",
            include_bytes!("../src/fs_hfsplus_node.rs"),
        ),
        (
            "src/fs_hfsplus_owned_create.rs",
            include_bytes!("../src/fs_hfsplus_owned_create.rs"),
        ),
        (
            "src/fs_hfsplus_owned_cuts.rs",
            include_bytes!("../src/fs_hfsplus_owned_cuts.rs"),
        ),
        (
            "src/fs_hfsplus_owned_namespace.rs",
            include_bytes!("../src/fs_hfsplus_owned_namespace.rs"),
        ),
        (
            "src/fs_hfsplus_owned_namespace_cuts.rs",
            include_bytes!("../src/fs_hfsplus_owned_namespace_cuts.rs"),
        ),
        (
            "src/fs_hfsplus_owned_namespace_native.rs",
            include_bytes!("../src/fs_hfsplus_owned_namespace_native.rs"),
        ),
        (
            "src/fs_hfsplus_owned_namespace_native_cuts.rs",
            include_bytes!("../src/fs_hfsplus_owned_namespace_native_cuts.rs"),
        ),
        (
            "src/fs_hfsplus_owned_prepare.rs",
            include_bytes!("../src/fs_hfsplus_owned_prepare.rs"),
        ),
        (
            "src/fs_hfsplus_owned_recovery.rs",
            include_bytes!("../src/fs_hfsplus_owned_recovery.rs"),
        ),
        (
            "src/fs_hfsplus_owned_resize.rs",
            include_bytes!("../src/fs_hfsplus_owned_resize.rs"),
        ),
        (
            "src/fs_hfsplus_owned_resize_commit.rs",
            include_bytes!("../src/fs_hfsplus_owned_resize_commit.rs"),
        ),
        (
            "src/fs_hfsplus_owned_resize_cuts.rs",
            include_bytes!("../src/fs_hfsplus_owned_resize_cuts.rs"),
        ),
        (
            "src/fs_hfsplus_owned_resize_forks_native.rs",
            include_bytes!("../src/fs_hfsplus_owned_resize_forks_native.rs"),
        ),
        (
            "src/fs_hfsplus_owned_resize_metadata.rs",
            include_bytes!("../src/fs_hfsplus_owned_resize_metadata.rs"),
        ),
        (
            "src/fs_hfsplus_owned_resize_native.rs",
            include_bytes!("../src/fs_hfsplus_owned_resize_native.rs"),
        ),
        (
            "src/fs_hfsplus_owned_resize_native_cuts.rs",
            include_bytes!("../src/fs_hfsplus_owned_resize_native_cuts.rs"),
        ),
        (
            "src/fs_hfsplus_owned_resize_recovery.rs",
            include_bytes!("../src/fs_hfsplus_owned_resize_recovery.rs"),
        ),
        (
            "src/fs_hfsplus_owned_transaction.rs",
            include_bytes!("../src/fs_hfsplus_owned_transaction.rs"),
        ),
        (
            "src/fs_hfsplus_tree.rs",
            include_bytes!("../src/fs_hfsplus_tree.rs"),
        ),
        ("src/fs_image.rs", include_bytes!("../src/fs_image.rs")),
        ("src/fs_jffs2.rs", include_bytes!("../src/fs_jffs2.rs")),
        (
            "src/fs_jffs2_audit.rs",
            include_bytes!("../src/fs_jffs2_audit.rs"),
        ),
        (
            "src/fs_jffs2_builder.rs",
            include_bytes!("../src/fs_jffs2_builder.rs"),
        ),
        (
            "src/fs_jffs2_builder_compression.rs",
            include_bytes!("../src/fs_jffs2_builder_compression.rs"),
        ),
        (
            "src/fs_jffs2_compression.rs",
            include_bytes!("../src/fs_jffs2_compression.rs"),
        ),
        (
            "src/fs_jffs2_edit.rs",
            include_bytes!("../src/fs_jffs2_edit.rs"),
        ),
        (
            "src/fs_jffs2_edit_compression.rs",
            include_bytes!("../src/fs_jffs2_edit_compression.rs"),
        ),
        (
            "src/fs_jffs2_edit_compression_tests.rs",
            include_bytes!("../src/fs_jffs2_edit_compression_tests.rs"),
        ),
        (
            "src/fs_jffs2_edit_file.rs",
            include_bytes!("../src/fs_jffs2_edit_file.rs"),
        ),
        (
            "src/fs_jffs2_edit_gc.rs",
            include_bytes!("../src/fs_jffs2_edit_gc.rs"),
        ),
        (
            "src/fs_jffs2_edit_journal.rs",
            include_bytes!("../src/fs_jffs2_edit_journal.rs"),
        ),
        (
            "src/fs_jffs2_edit_namespace.rs",
            include_bytes!("../src/fs_jffs2_edit_namespace.rs"),
        ),
        (
            "src/fs_jffs2_tree.rs",
            include_bytes!("../src/fs_jffs2_tree.rs"),
        ),
        ("src/fs_jfs.rs", include_bytes!("../src/fs_jfs.rs")),
        (
            "src/fs_jfs_audit.rs",
            include_bytes!("../src/fs_jfs_audit.rs"),
        ),
        (
            "src/fs_jfs_edit.rs",
            include_bytes!("../src/fs_jfs_edit.rs"),
        ),
        (
            "src/fs_jfs_edit_allocation.rs",
            include_bytes!("../src/fs_jfs_edit_allocation.rs"),
        ),
        (
            "src/fs_jfs_edit_journal.rs",
            include_bytes!("../src/fs_jfs_edit_journal.rs"),
        ),
        (
            "src/fs_jfs_edit_namespace.rs",
            include_bytes!("../src/fs_jfs_edit_namespace.rs"),
        ),
        (
            "src/fs_jfs_edit_rename.rs",
            include_bytes!("../src/fs_jfs_edit_rename.rs"),
        ),
        (
            "src/fs_jfs_edit_rollover.rs",
            include_bytes!("../src/fs_jfs_edit_rollover.rs"),
        ),
        (
            "src/fs_jfs_tree.rs",
            include_bytes!("../src/fs_jfs_tree.rs"),
        ),
        (
            "src/fs_maintenance.rs",
            include_bytes!("../src/fs_maintenance.rs"),
        ),
        (
            "src/fs_maintenance_audit.rs",
            include_bytes!("../src/fs_maintenance_audit.rs"),
        ),
        (
            "src/fs_maintenance_format.rs",
            include_bytes!("../src/fs_maintenance_format.rs"),
        ),
        (
            "src/fs_maintenance_format_tests.rs",
            include_bytes!("../src/fs_maintenance_format_tests.rs"),
        ),
        ("src/fs_ntfs.rs", include_bytes!("../src/fs_ntfs.rs")),
        (
            "src/fs_ntfs_audit.rs",
            include_bytes!("../src/fs_ntfs_audit.rs"),
        ),
        (
            "src/fs_ntfs_bootstrap.rs",
            include_bytes!("../src/fs_ntfs_bootstrap.rs"),
        ),
        (
            "src/fs_ntfs_compressed.rs",
            include_bytes!("../src/fs_ntfs_compressed.rs"),
        ),
        (
            "src/fs_ntfs_logfile/checkpoint.rs",
            include_bytes!("../src/fs_ntfs_logfile/checkpoint.rs"),
        ),
        (
            "src/fs_ntfs_logfile/checkpoint_dumps.rs",
            include_bytes!("../src/fs_ntfs_logfile/checkpoint_dumps.rs"),
        ),
        (
            "src/fs_ntfs_logfile/client_record.rs",
            include_bytes!("../src/fs_ntfs_logfile/client_record.rs"),
        ),
        (
            "src/fs_ntfs_logfile/pages.rs",
            include_bytes!("../src/fs_ntfs_logfile/pages.rs"),
        ),
        (
            "src/fs_ntfs_logfile/record.rs",
            include_bytes!("../src/fs_ntfs_logfile/record.rs"),
        ),
        (
            "src/fs_ntfs_logfile/record_links.rs",
            include_bytes!("../src/fs_ntfs_logfile/record_links.rs"),
        ),
        (
            "src/fs_ntfs_logfile/restart_selection.rs",
            include_bytes!("../src/fs_ntfs_logfile/restart_selection.rs"),
        ),
        (
            "src/fs_ntfs_logfile/restart_table.rs",
            include_bytes!("../src/fs_ntfs_logfile/restart_table.rs"),
        ),
        (
            "src/fs_ntfs_logfile/table_entries.rs",
            include_bytes!("../src/fs_ntfs_logfile/table_entries.rs"),
        ),
        (
            "src/fs_ntfs_logfile/native_analysis_context.rs",
            include_bytes!("fs_ntfs_logfile/native_analysis_context.rs"),
        ),
        (
            "src/fs_ntfs_logfile.rs",
            include_bytes!("../src/fs_ntfs_logfile.rs"),
        ),
        (
            "src/fs_ntfs_metadata.rs",
            include_bytes!("../src/fs_ntfs_metadata.rs"),
        ),
        (
            "src/fs_ntfs_secure.rs",
            include_bytes!("../src/fs_ntfs_secure.rs"),
        ),
        (
            "src/fs_ntfs_security.rs",
            include_bytes!("../src/fs_ntfs_security.rs"),
        ),
        (
            "src/fs_ntfs_stream.rs",
            include_bytes!("../src/fs_ntfs_stream.rs"),
        ),
        (
            "src/fs_ntfs_tree.rs",
            include_bytes!("../src/fs_ntfs_tree.rs"),
        ),
        (
            "src/fs_ntfs_usn.rs",
            include_bytes!("../src/fs_ntfs_usn.rs"),
        ),
        (
            "src/fs_ntfs_usn_extract.rs",
            include_bytes!("../src/fs_ntfs_usn_extract.rs"),
        ),
        (
            "src/fs_pagination.rs",
            include_bytes!("../src/fs_pagination.rs"),
        ),
        (
            "src/fs_pipeline.rs",
            include_bytes!("../src/fs_pipeline.rs"),
        ),
        ("src/fs_storage.rs", include_bytes!("../src/fs_storage.rs")),
        ("src/fs_undo.rs", include_bytes!("../src/fs_undo.rs")),
        ("src/fs_xfs.rs", include_bytes!("../src/fs_xfs.rs")),
        (
            "src/fs_xfs_audit.rs",
            include_bytes!("../src/fs_xfs_audit.rs"),
        ),
        (
            "src/fs_xfs_tree.rs",
            include_bytes!("../src/fs_xfs_tree.rs"),
        ),
        ("src/gpt.rs", include_bytes!("../src/gpt.rs")),
        ("src/guid.rs", include_bytes!("../src/guid.rs")),
        ("src/io.rs", include_bytes!("../src/io.rs")),
        ("src/layout.rs", include_bytes!("../src/layout.rs")),
        ("src/lib.rs", include_bytes!("../src/lib.rs")),
        ("src/partition.rs", include_bytes!("../src/partition.rs")),
        ("src/payload.rs", include_bytes!("../src/payload.rs")),
        ("src/platform.rs", include_bytes!("../src/platform.rs")),
        ("src/recovery.rs", include_bytes!("../src/recovery.rs")),
        ("src/storage.rs", include_bytes!("../src/storage.rs")),
        ("src/uefi.rs", include_bytes!("../src/uefi.rs")),
        (
            "src/volume_probe.rs",
            include_bytes!("../src/volume_probe.rs"),
        ),
        (
            "integration/maintenance/ext-symlink-oracle.py",
            include_bytes!("../integration/maintenance/ext-symlink-oracle.py"),
        ),
        (
            "integration/maintenance/ext-symlink-cuts-verify.py",
            include_bytes!("../integration/maintenance/ext-symlink-cuts-verify.py"),
        ),
        (
            "integration/maintenance/ext-hardlink-oracle.py",
            include_bytes!("../integration/maintenance/ext-hardlink-oracle.py"),
        ),
        (
            "integration/maintenance/ext-hardlink-cuts-verify.py",
            include_bytes!("../integration/maintenance/ext-hardlink-cuts-verify.py"),
        ),
        (
            "integration/maintenance/ext-sparse-extension-oracle.py",
            include_bytes!("../integration/maintenance/ext-sparse-extension-oracle.py"),
        ),
        (
            "integration/maintenance/ext-sparse-extension-cuts-verify.py",
            include_bytes!("../integration/maintenance/ext-sparse-extension-cuts-verify.py"),
        ),
        (
            "src/fs_ext_edit_allocation_symlink_tests.rs",
            include_bytes!("fs_ext_edit_allocation_symlink_tests.rs"),
        ),
        (
            "src/fs_ext_edit_allocation_sparse_tests.rs",
            include_bytes!("fs_ext_edit_allocation_sparse_tests.rs"),
        ),
        (
            "integration/maintenance/ext-overwrite-oracle.py",
            include_bytes!("../integration/maintenance/ext-overwrite-oracle.py"),
        ),
        (
            "integration/maintenance/ext-overwrite-cuts-verify.py",
            include_bytes!("../integration/maintenance/ext-overwrite-cuts-verify.py"),
        ),
        (
            "src/fs_ext_edit_allocation_overwrite_tests.rs",
            include_bytes!("fs_ext_edit_allocation_overwrite_tests.rs"),
        ),
        (
            "tests/fixtures/ext2_clean.rs",
            include_bytes!("../tests/fixtures/ext2_clean.rs"),
        ),
        (
            "tests/fixtures/ntfs_clean.rs",
            include_bytes!("../tests/fixtures/ntfs_clean.rs"),
        ),
        (
            "tests/fixtures/jfs_clean.rs",
            include_bytes!("../tests/fixtures/jfs_clean.rs"),
        ),
        (
            "tests/fixtures/hfsplus_clean.rs",
            include_bytes!("../tests/fixtures/hfsplus_clean.rs"),
        ),
        (
            "tests/fixtures/jffs2_clean.rs",
            include_bytes!("../tests/fixtures/jffs2_clean.rs"),
        ),
        ("Cargo.toml", include_bytes!("../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../Cargo.lock")),
        (
            "integration/maintenance/ext-owned-oracle.py",
            include_bytes!("../integration/maintenance/ext-owned-oracle.py"),
        ),
        (
            "integration/maintenance/ext-owned-cuts-verify.py",
            include_bytes!("../integration/maintenance/ext-owned-cuts-verify.py"),
        ),
        (
            "integration/maintenance/ext-truncate-oracle.py",
            include_bytes!("../integration/maintenance/ext-truncate-oracle.py"),
        ),
        (
            "integration/maintenance/ext-truncate-cuts-verify.py",
            include_bytes!("../integration/maintenance/ext-truncate-cuts-verify.py"),
        ),
        (
            "integration/maintenance/ext-directory-growth-oracle.py",
            include_bytes!("../integration/maintenance/ext-directory-growth-oracle.py"),
        ),
        (
            "integration/maintenance/ext-directory-growth-cuts-verify.py",
            include_bytes!("../integration/maintenance/ext-directory-growth-cuts-verify.py"),
        ),
        (
            "integration/maintenance/ext-namespace-oracle.py",
            include_bytes!("../integration/maintenance/ext-namespace-oracle.py"),
        ),
        (
            "integration/maintenance/ext-namespace-v4-cuts-verify.py",
            include_bytes!("../integration/maintenance/ext-namespace-v4-cuts-verify.py"),
        ),
        (
            "integration/maintenance/ext-namespace-cuts-verify.py",
            include_bytes!("../integration/maintenance/ext-namespace-cuts-verify.py"),
        ),
        (
            "src/fs_ntfs_logfile/active_seed.rs",
            include_bytes!("fs_ntfs_logfile/active_seed.rs"),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery.rs",
            include_bytes!("fs_ntfs_logfile/tail_discovery.rs"),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary.rs",
            include_bytes!("fs_ntfs_logfile/tail_discovery/ordinary.rs"),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/overlay.rs",
            include_bytes!("fs_ntfs_logfile/tail_discovery/ordinary/overlay.rs"),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor.rs",
            include_bytes!("fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor.rs"),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis.rs",
            include_bytes!(
                "fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis.rs"
            ),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/partial.rs",
            include_bytes!("fs_ntfs_logfile/tail_discovery/ordinary/partial.rs"),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/open_analysis.rs",
            include_bytes!(
                "fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis/open_analysis.rs"
            ),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis.rs",
            include_bytes!(
                "fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis/dirty_analysis.rs"
            ),
        ),
        (
            "src/fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis.rs",
            include_bytes!(
                "fs_ntfs_logfile/tail_discovery/ordinary/overlay/successor/checkpoint_analysis/replay_analysis.rs"
            ),
        ),
    ]
}

/// Native allocation bitmap and final regular-file map, independent of planner roles.
fn ordered_old_mask(
    original: &[u8],
    grown: &[u8],
    inode: u32,
    old_length: usize,
    bs: usize,
    r: &Resources,
) -> Vec<(usize, usize)> {
    let storage = Model::new(grown);
    let (decoder, proof) = super::super::ExtDecoder::open_native_clean(&storage, 83, r).unwrap();
    let map = decoder.file_map(inode, 65536, r, false).unwrap();
    let old_storage = Model::new(original);
    let old_context = if old_length != 0 {
        let (old_decoder, old_proof) =
            super::super::ExtDecoder::open_native_clean(&old_storage, 84, r).unwrap();
        let old_map = old_decoder.file_map(inode, 65536, r, false).unwrap();
        assert_eq!(old_map.length, old_length as u64);
        Some((old_map, old_decoder, old_proof))
    } else {
        None
    };
    let le = |at| u32::from_le_bytes(original[at..at + 4].try_into().unwrap()) as usize;
    let first = le(1024 + 20);
    let per_group = le(1024 + 32);
    let descriptor = if bs == 1024 { 2 * bs } else { bs };
    let mut mask = Vec::new();
    for extent in &map.extents {
        let crate::fs_file::ExtentKind::Data(physical) = extent.kind else {
            panic!("native corpus regular file must not be sparse")
        };
        assert_eq!(physical as usize % bs, 0);
        for within in (0..extent.length as usize).step_by(bs) {
            let at = physical as usize + within;
            let block = at / bs;
            let relative = block.checked_sub(first).unwrap();
            let group = relative / per_group;
            let bit = relative % per_group;
            let bitmap = le(descriptor + group * 32) * bs;
            let allocated = original[bitmap + bit / 8] & (1 << (bit % 8)) != 0;
            let logical = extent.offset as usize + within;
            if !allocated {
                mask.push((at, bs));
            } else if !old_length.is_multiple_of(bs) && logical == old_length / bs * bs {
                let old_map = &old_context.as_ref().unwrap().0;
                let old_extent = old_map
                    .extents
                    .iter()
                    .find(|extent| {
                        logical as u64 >= extent.offset
                            && (logical as u64) - extent.offset < extent.length
                    })
                    .unwrap();
                let crate::fs_file::ExtentKind::Data(old_physical) = old_extent.kind else {
                    panic!("original regular tail must be mapped")
                };
                assert_eq!(old_physical + logical as u64 - old_extent.offset, at as u64);
                mask.push((at + old_length % bs, bs - old_length % bs));
            } else {
                assert!(
                    logical + bs <= old_length,
                    "unexpected original allocated new regular data block"
                );
            }
        }
    }
    drop(old_context);
    drop(map);
    drop(decoder);
    drop(proof);
    mask.sort_unstable();
    for pair in mask.windows(2) {
        assert!(pair[0].0 + pair[0].1 <= pair[1].0);
    }
    mask
}
fn ordered_old_equal(
    a: &[u8],
    b: &[u8],
    bs: usize,
    journal: &[u32],
    mask: &[(usize, usize)],
) -> bool {
    a.len() == b.len()
        && a.chunks(bs)
            .zip(b.chunks(bs))
            .enumerate()
            .all(|(block, (a, b))| {
                journal.contains(&(block as u32))
                    || a.iter().zip(b).enumerate().all(|(within, (a, b))| {
                        let at = block * bs + within;
                        a == b
                            || mask
                                .iter()
                                .any(|(start, len)| at >= *start && at - start < *len)
                    })
            })
}

fn public_limits() -> crate::fs_ext::ExtJournalLimits {
    let limits = limits();
    crate::fs_ext::ExtJournalLimits {
        audit: limits.audit,
        file_blocks: limits.file_blocks,
        affected_blocks: limits.affected_blocks,
        affected_bytes: limits.affected_bytes,
    }
}
fn public_contents(
    s: &crate::fs_ext::ExtJournalSession<Model>,
    name: &[u8],
    expected: &[u8],
    r: &Resources,
) {
    let file = s.file_at(&names(name), &r.cancellation).unwrap();
    let mut actual = vec![0; expected.len()];
    let mut at = 0;
    while at < actual.len() {
        let n = s
            .read_at(&file, at as u64, &mut actual[at..], &r.cancellation)
            .unwrap();
        assert!(n > 0);
        at += n;
    }
    assert_eq!(
        s.read_at(&file, at as u64, &mut [0], &r.cancellation)
            .unwrap(),
        0
    );
    assert_eq!(actual, expected);
}
fn ordered_operation(
    s: &mut crate::fs_ext::ExtJournalSession<Model>,
    operation: &str,
    append: &Input,
    r: &Resources,
) -> io::Result<()> {
    if operation == "extend" {
        let file = s.file_at(&names(b"payload"), &r.cancellation)?;
        s.append(&file, append, planning(), &r.cancellation)
    } else {
        assert_eq!(operation, "create");
        let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o100644);
        s.create_file(
            &[],
            b"new-ordered",
            &metadata,
            &append.bytes,
            planning(),
            &r.cancellation,
        )
    }
}
#[test]
#[ignore = "requires pinned e2fsprogs corpus and fresh ordered evidence directory"]
fn native_owned_ext3_ordered_allocation_cuts() {
    let corpus = required("PARTMGR_EXT_OWNED_CORPUS");
    let root = required("PARTMGR_GATE_SOURCE_ROOT");
    let out = required("PARTMGR_EXT_ORDERED_EVIDENCE");
    fs::create_dir(&out).unwrap();
    fs::create_dir(out.join("images")).unwrap();
    let receipt = checked(
        &corpus.join("receipt.json"),
        "1fc841600d01124b9de21d56d9fea357dc89a0f56d5f01db108fc7cd955705cf",
    );
    fs::write(out.join("fixture-receipt.json"), receipt).unwrap();
    let models = checked(
        &corpus.join("models.tsv"),
        "4d5197032c6b09f8a36d65a8db2760dd1f66c2dac9d529cfd48b7fd74ad90598",
    );
    let snapshot = || {
        let mut manifest = String::new();
        for (name, bytes) in compiled_sources() {
            assert_eq!(fs::read(root.join(name)).unwrap(), *bytes);
            writeln!(manifest, "{}  {name}", hash(bytes)).unwrap();
        }
        manifest
    };
    let before = snapshot();
    fs::write(out.join("source-start.sha256"), &before).unwrap();
    for (name, bytes) in compiled_sources() {
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fs::write(
        out.join("gate-binary"),
        fs::read(std::env::current_exe().unwrap()).unwrap(),
    )
    .unwrap();
    let mut manifest = String::from(
        "bs\toperation\tcase\tevent\tmodel\tfault_kind\tprefix\tpre_sha256\tpre_path\tretried_sha256\tretried_path\tresult\n",
    );
    let mut observations = String::new();
    let mut errors = String::new();
    let mut total = 0;
    for line in std::str::from_utf8(&models).unwrap().lines() {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 12);
        let bs: usize = f[0].parse().unwrap();
        let original = checked(&corpus.join(f[1]), f[2]);
        let payload = checked(&corpus.join(f[3]), f[4]);
        let append = Input {
            bytes: checked(&corpus.join(f[5]), f[6]),
            id: ObjectId {
                source: 71,
                generation: 1,
                native: vec![1],
            },
        };
        let expected = checked(&corpus.join(f[7]), f[8]);
        let unrelated = checked(&corpus.join(f[9]), f[10]);
        assert_eq!(
            [payload.as_slice(), append.bytes.as_slice()].concat(),
            expected
        );
        for operation in ["extend", "create"] {
            let r = resources();
            let bootstrap =
                bootstrap::Bootstrap::read(&Model::new(&original), 65536, 32_000_000, &r).unwrap();
            // Exclude journal data only: its indirect mapping blocks remain exact homes.
            let journal = bootstrap.physical_blocks.clone();
            fs::write(
                out.join(format!("journal-map-b{bs}.tsv")),
                journal.iter().map(|v| format!("{v}\n")).collect::<String>(),
            )
            .unwrap();
            drop(bootstrap);
            let mut baseline =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            ordered_operation(&mut baseline, operation, &append, &r).unwrap();
            let name = if operation == "extend" {
                b"payload".as_slice()
            } else {
                b"new-ordered".as_slice()
            };
            public_contents(
                &baseline,
                name,
                if operation == "extend" {
                    &expected
                } else {
                    &append.bytes
                },
                &r,
            );
            public_contents(&baseline, b"unrelated", &unrelated, &r);
            let file = baseline.file_at(&names(name), &r.cancellation).unwrap();
            let inode = file.inode_number();
            drop(file);
            let (after, state) = baseline.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            let trace = after.trace.clone();
            let grown = after.visible;
            let mask = ordered_old_mask(
                &original,
                &grown,
                inode,
                if operation == "extend" {
                    payload.len()
                } else {
                    0
                },
                bs,
                &r,
            );
            let mut ranges = String::from("offset\tbytes\n");
            for (at, len) in &mask {
                writeln!(ranges, "{at}\t{len}").unwrap();
            }
            fs::write(out.join(format!("mask-b{bs}-{operation}.tsv")), ranges).unwrap();
            let mut events = String::from("event\tkind\tbytes\n");
            for (index, event) in trace.iter().enumerate() {
                match event {
                    Event::Write(n) => writeln!(events, "{}\twrite\t{n}", index + 1).unwrap(),
                    Event::Flush => writeln!(events, "{}\tflush\t0", index + 1).unwrap(),
                }
            }
            fs::write(out.join(format!("events-b{bs}-{operation}.tsv")), events).unwrap();
            let (_, baseline_path) = saved(&out, &grown);
            writeln!(
                observations,
                "bs={bs} operation={operation} events={} baseline={baseline_path}",
                trace.len()
            )
            .unwrap();
            assert_eq!(r.memory.used(), 0);
            let mut case = 0;
            for (event, kind) in trace.iter().enumerate() {
                let prefixes = match kind {
                    Event::Write(n) => vec![0, n / 2, *n],
                    Event::Flush => vec![0],
                };
                for immediate in [false, true] {
                    for persist in [false, true] {
                        for prefix in &prefixes {
                            case += 1;
                            total += 1;
                            let r = resources();
                            let mut model = Model::new(&original);
                            model.cut = event + 1;
                            model.prefix = *prefix;
                            model.immediate = immediate;
                            model.persist = persist;
                            let mut s =
                                crate::fs_ext::ExtJournalSession::open(model, public_limits(), &r)
                                    .unwrap();
                            let error = ordered_operation(&mut s, operation, &append, &r)
                                .expect_err("ordered cut must fail");
                            writeln!(errors,"bs={bs} operation={operation} case={case} event={} cause={error:?}",event+1).unwrap();
                            let (mut cut, _) = s.into_storage();
                            assert!(cut.hit);
                            let (prehash, prepath) = saved(&out, &cut.durable);
                            cut.visible.clone_from(&cut.durable);
                            cut.cut = usize::MAX;
                            cut.trace.clear();
                            let mut retry = crate::fs_ext::ExtJournalSession::open_for_recovery(
                                cut,
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            retry.recover(&r.cancellation).unwrap();
                            let (recovered, state) = retry.into_storage();
                            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
                            let is_old = ordered_old_equal(
                                &recovered.visible,
                                &original,
                                bs,
                                &journal,
                                &mask,
                            );
                            let is_new = home_equal(&recovered.visible, &grown, bs, &journal);
                            assert_ne!(is_old, is_new, "ordered outcome must be unambiguous");
                            let result = if is_old { "old" } else { "new" };
                            let retry_s = crate::fs_ext::ExtJournalSession::open(
                                Model::new(&recovered.visible),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            public_contents(
                                &retry_s,
                                b"payload",
                                if operation == "extend" && is_new {
                                    &expected
                                } else {
                                    &payload
                                },
                                &r,
                            );
                            public_contents(&retry_s, b"unrelated", &unrelated, &r);
                            if operation == "create" {
                                if is_new {
                                    public_contents(&retry_s, b"new-ordered", &append.bytes, &r)
                                } else {
                                    assert!(
                                        retry_s
                                            .file_at(&names(b"new-ordered"), &r.cancellation)
                                            .is_err()
                                    );
                                }
                            }
                            drop(retry_s);
                            let (retryhash, retrypath) = saved(&out, &recovered.visible);
                            writeln!(manifest,"{bs}\t{operation}\t{case}\t{}\t{}\t{}\t{prefix}\t{prehash}\t{prepath}\t{retryhash}\t{retrypath}\t{result}",event+1,if immediate {"immediate"} else {"volatile"},match kind {Event::Write(_)=>"write",Event::Flush=>if persist {"flush-persist"} else {"flush-none"}}).unwrap();
                            assert_eq!(r.memory.used(), 0);
                        }
                    }
                }
            }
        }
        // All three operations retain the same public owner and its evolving generation.
        let r = resources();
        let persisted = Rc::new(RefCell::new(original.clone()));
        let mut model = Model::new(&original);
        model.snapshot = Some(persisted.clone());
        let mut repeat =
            crate::fs_ext::ExtJournalSession::open(model, public_limits(), &r).unwrap();
        let payload_path = format!("public-repeat-b{bs}-payload.bin");
        let created_path = format!("public-repeat-b{bs}-created.bin");
        let twice_path = format!("public-repeat-b{bs}-created-twice.bin");
        let twice = [append.bytes.as_slice(), append.bytes.as_slice()].concat();
        fs::write(out.join(&payload_path), &expected).unwrap();
        fs::write(out.join(&created_path), &append.bytes).unwrap();
        fs::write(out.join(&twice_path), &twice).unwrap();
        let mut steps =
            String::from("step\timage_sha256\timage_path\tpayload_path\tcreated_payload_path\n");
        let mut capture = |step: &str, created: &str| {
            let (hash, path) = saved(&out, &persisted.borrow());
            writeln!(steps, "{step}\t{hash}\t{path}\t{payload_path}\t{created}").unwrap();
        };
        ordered_operation(&mut repeat, "extend", &append, &r).unwrap();
        public_contents(&repeat, b"payload", &expected, &r);
        capture("append", "-");
        ordered_operation(&mut repeat, "create", &append, &r).unwrap();
        public_contents(&repeat, b"new-ordered", &append.bytes, &r);
        capture("create", &created_path);
        let created = repeat
            .file_at(&names(b"new-ordered"), &r.cancellation)
            .unwrap();
        repeat
            .append(&created, &append, planning(), &r.cancellation)
            .unwrap();
        drop(created);
        public_contents(&repeat, b"new-ordered", &twice, &r);
        public_contents(&repeat, b"payload", &expected, &r);
        public_contents(&repeat, b"unrelated", &unrelated, &r);
        capture("append-created", &twice_path);
        fs::write(out.join(format!("public-repeat-b{bs}.tsv")), steps).unwrap();
        let (repeated, state) = repeat.into_storage();
        assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
        assert_eq!(repeated.visible, *persisted.borrow());
        assert_eq!(r.memory.used(), 0);
        assert_eq!(hash(&fs::read(corpus.join(f[1])).unwrap()), f[2]);
    }
    assert_eq!(snapshot(), before);
    fs::write(out.join("source-end.sha256"), snapshot()).unwrap();
    fs::write(out.join("cuts.tsv"), manifest).unwrap();
    fs::write(out.join("observations.txt"), observations).unwrap();
    fs::write(out.join("cut-errors.txt"), errors).unwrap();
    checked(
        &corpus.join("receipt.json"),
        "1fc841600d01124b9de21d56d9fea357dc89a0f56d5f01db108fc7cd955705cf",
    );
    checked(
        &corpus.join("models.tsv"),
        "4d5197032c6b09f8a36d65a8db2760dd1f66c2dac9d529cfd48b7fd74ad90598",
    );
    fs::write(out.join("report.txt"),format!("complete=true\ncases={total}\nscope=public ordered classic ext3 append/create simulated cut cold recovery; independent native verifier required; no kernel crash or broader mutation qualification\n")).unwrap();
}

// Fragment for the existing owned_native_cuts module; reuses its bounded Model,
// pinned corpus helpers and compiled_sources(). Namespace dispatch uses the public API.
fn namespace_native_operation(
    s: &mut crate::fs_ext::ExtJournalSession<Model>,
    op: &str,
    r: &Resources,
) -> io::Result<()> {
    let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o40755);
    let sub = names(b"sub");
    match op {
        "mkdir" => s.create_directory(&[], b"new-dir", &metadata, planning(), &r.cancellation),
        "rename" => s.rename(
            &[],
            b"payload",
            &[],
            b"renamed",
            planning(),
            &r.cancellation,
        ),
        "move" => s.rename(&[], b"payload", &sub, b"moved", planning(), &r.cancellation),
        "unlinkalias" => s.unlink_file(&[], b"alias", 946684800, planning(), &r.cancellation),
        "unlinkpayload" => s.unlink_file(&[], b"payload", 946684800, planning(), &r.cancellation),
        "rmdirsub" => s.remove_directory(&[], b"sub", 946684800, planning(), &r.cancellation),
        _ => panic!("unknown namespace operation"),
    }
}
fn namespace_native_contents(
    s: &crate::fs_ext::ExtJournalSession<Model>,
    op: &str,
    is_new: bool,
    payload: &[u8],
    unrelated: &[u8],
    r: &Resources,
) {
    let payload_path = if is_new && op == "rename" {
        names(b"renamed").to_vec()
    } else if is_new && op == "move" {
        vec![names(b"sub")[0].clone(), names(b"moved")[0].clone()]
    } else {
        names(b"payload").to_vec()
    };
    if is_new && op == "unlinkpayload" {
        assert!(s.file_at(&payload_path, &r.cancellation).is_err());
    } else {
        let file = s.file_at(&payload_path, &r.cancellation).unwrap();
        let mut bytes = vec![0; payload.len() + 1];
        let n = s.read_at(&file, 0, &mut bytes, &r.cancellation).unwrap();
        bytes.truncate(n);
        assert_eq!(bytes, payload);
    }
    public_contents(s, b"unrelated", unrelated, r);
    if is_new && op == "unlinkalias" {
        assert!(s.file_at(&names(b"alias"), &r.cancellation).is_err());
    } else {
        public_contents(s, b"alias", unrelated, r);
    }
}
#[test]
#[ignore = "requires pinned e2fsprogs corpus, fresh namespace evidence and independent native verification"]
fn native_owned_ext3_ordered_namespace_cuts() {
    let corpus = required("PARTMGR_EXT_OWNED_CORPUS");
    let root = required("PARTMGR_GATE_SOURCE_ROOT");
    let out = required("PARTMGR_EXT_NAMESPACE_EVIDENCE");
    fs::create_dir(&out).unwrap();
    fs::create_dir(out.join("images")).unwrap();
    let receipt = checked(
        &corpus.join("receipt.json"),
        "1fc841600d01124b9de21d56d9fea357dc89a0f56d5f01db108fc7cd955705cf",
    );
    fs::write(out.join("fixture-receipt.json"), receipt).unwrap();
    let models = checked(
        &corpus.join("models.tsv"),
        "4d5197032c6b09f8a36d65a8db2760dd1f66c2dac9d529cfd48b7fd74ad90598",
    );
    let snapshot = || {
        let mut manifest = String::new();
        for (name, bytes) in compiled_sources() {
            assert_eq!(fs::read(root.join(name)).unwrap(), *bytes);
            writeln!(manifest, "{}  {name}", hash(bytes)).unwrap();
        }
        manifest
    };
    let before = snapshot();
    fs::write(out.join("source-start.sha256"), &before).unwrap();
    for (name, bytes) in compiled_sources() {
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fs::write(
        out.join("gate-binary"),
        fs::read(std::env::current_exe().unwrap()).unwrap(),
    )
    .unwrap();
    let mut manifest = String::from(
        "bs\toperation\tcase\tevent\tmodel\tfault_kind\tprefix\tpre_sha256\tpre_path\tretried_sha256\tretried_path\tresult\n",
    );
    let mut observations = String::new();
    let mut errors = String::new();
    let mut total = 0usize;
    for line in std::str::from_utf8(&models).unwrap().lines() {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 12);
        let bs: usize = f[0].parse().unwrap();
        let original = checked(&corpus.join(f[1]), f[2]);
        let payload = checked(&corpus.join(f[3]), f[4]);
        let unrelated = checked(&corpus.join(f[9]), f[10]);
        let r = resources();
        let boot =
            bootstrap::Bootstrap::read(&Model::new(&original), 65536, 32_000_000, &r).unwrap();
        let journal = boot.physical_blocks.clone();
        drop(boot);
        assert_eq!(r.memory.used(), 0);
        fs::write(
            out.join(format!("journal-map-b{bs}.tsv")),
            journal.iter().map(|n| format!("{n}\n")).collect::<String>(),
        )
        .unwrap();
        for operation in [
            "mkdir",
            "rename",
            "move",
            "unlinkalias",
            "unlinkpayload",
            "rmdirsub",
        ] {
            let r = resources();
            let mut baseline =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            namespace_native_operation(&mut baseline, operation, &r).unwrap();
            namespace_native_contents(&baseline, operation, true, &payload, &unrelated, &r);
            let (baseline, state) = baseline.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            assert_eq!(baseline.visible, baseline.durable);
            let trace = baseline.trace.clone();
            let expected = baseline.visible;
            assert!(!home_equal(&original, &expected, bs, &journal));
            let (h, path) = saved(&out, &expected);
            writeln!(
                observations,
                "bs={bs} operation={operation} events={} baseline={path}",
                trace.len()
            )
            .unwrap();
            assert_eq!(path, format!("images/{h}.raw"));
            let mut events = String::from("event\tkind\tbytes\n");
            for (i, event) in trace.iter().enumerate() {
                match event {
                    Event::Write(n) => writeln!(events, "{}\twrite\t{n}", i + 1).unwrap(),
                    Event::Flush => writeln!(events, "{}\tflush\t0", i + 1).unwrap(),
                }
            }
            fs::write(out.join(format!("events-b{bs}-{operation}.tsv")), events).unwrap();
            assert_eq!(r.memory.used(), 0);
            let mut case = 0usize;
            for (event, kind) in trace.iter().enumerate() {
                let prefixes = match kind {
                    Event::Write(n) => vec![0, n / 2, *n],
                    Event::Flush => vec![0],
                };
                for immediate in [false, true] {
                    for persist in [false, true] {
                        for prefix in &prefixes {
                            case += 1;
                            total += 1;
                            let r = resources();
                            let mut model = Model::new(&original);
                            model.cut = event + 1;
                            model.prefix = *prefix;
                            model.immediate = immediate;
                            model.persist = persist;
                            let mut owner =
                                crate::fs_ext::ExtJournalSession::open(model, public_limits(), &r)
                                    .unwrap();
                            let error =
                                namespace_native_operation(&mut owner, operation, &r).unwrap_err();
                            writeln!(
                                errors,
                                "bs={bs} operation={operation} case={case} error={error:?}"
                            )
                            .unwrap();
                            assert!(error.to_string().contains("owned native cut"));
                            let (model, state) = owner.into_storage();
                            assert!(model.hit);
                            assert_eq!(state, crate::fs_ext::ExtJournalState::NeedsRecovery);
                            let (prehash, prepath) = saved(&out, &model.durable);
                            let mut cold = crate::fs_ext::ExtJournalSession::open_for_recovery(
                                Model::new(&model.durable),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            cold.recover(&r.cancellation).unwrap();
                            let (recovered, state) = cold.into_storage();
                            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
                            assert_eq!(recovered.visible, recovered.durable);
                            let old = home_equal(&recovered.visible, &original, bs, &journal);
                            let new = home_equal(&recovered.visible, &expected, bs, &journal);
                            assert_ne!(
                                old,
                                new,
                                "namespace partial outcome {bs} {operation} event={} prefix={prefix}",
                                event + 1
                            );
                            let result = if old { "old" } else { "new" };
                            let check = crate::fs_ext::ExtJournalSession::open(
                                Model::new(&recovered.visible),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            namespace_native_contents(
                                &check, operation, new, &payload, &unrelated, &r,
                            );
                            drop(check);
                            let (retryhash, retrypath) = saved(&out, &recovered.visible);
                            writeln!(manifest,"{bs}\t{operation}\t{case}\t{}\t{}\t{}\t{prefix}\t{prehash}\t{prepath}\t{retryhash}\t{retrypath}\t{result}",event+1,if immediate{"immediate"}else{"volatile"},match kind{Event::Write(_)=>"write",Event::Flush=>if persist{"flush-persist"}else{"flush-none"}}).unwrap();
                            assert_eq!(r.memory.used(), 0);
                        }
                    }
                }
            }
        }
        assert_eq!(hash(&fs::read(corpus.join(f[1])).unwrap()), f[2]);
    }
    assert_eq!(snapshot(), before);
    fs::write(out.join("source-end.sha256"), snapshot()).unwrap();
    fs::write(out.join("namespace-cuts.tsv"), manifest).unwrap();
    fs::write(out.join("observations.txt"), observations).unwrap();
    fs::write(out.join("cut-errors.txt"), errors).unwrap();
    checked(
        &corpus.join("receipt.json"),
        "1fc841600d01124b9de21d56d9fea357dc89a0f56d5f01db108fc7cd955705cf",
    );
    checked(
        &corpus.join("models.tsv"),
        "4d5197032c6b09f8a36d65a8db2760dd1f66c2dac9d529cfd48b7fd74ad90598",
    );
    fs::write(out.join("report.txt"),format!("complete=true\ncases={total}\nscope=public ordered namespace modeled cuts, exact OLD/NEW homes; independent native verification required; offline modeled qualification only; no kernel or hardware crash claim\n")).unwrap();
}

fn namespace_v4_operation(
    s: &mut crate::fs_ext::ExtJournalSession<Model>,
    op: &str,
    r: &Resources,
) -> io::Result<()> {
    let metadata = crate::fs_ext_edit::ExtCreateMetadata::zeroed(0o40755);
    let left = vec![NativeName::Bytes(b"left".to_vec())];
    let right = vec![NativeName::Bytes(b"right".to_vec())];
    let session_dir = vec![
        NativeName::Bytes(b"right".to_vec()),
        NativeName::Bytes(b"session-dir".to_vec()),
    ];
    match op {
        "move-directory" | "move-tree" => s.rename(
            &left,
            b"tree",
            &right,
            b"tree-moved",
            planning(),
            &r.cancellation,
        ),
        "unlink-indirect" => {
            s.unlink_file(&[], b"indirect", 946684800, planning(), &r.cancellation)
        }
        "mkdir-session" => s.create_directory(
            &right,
            b"session-dir",
            &metadata,
            planning(),
            &r.cancellation,
        ),
        "move-payload" => s.rename(
            &[],
            b"payload",
            &session_dir,
            b"payload",
            planning(),
            &r.cancellation,
        ),
        "rename-payload" => s.rename(
            &session_dir,
            b"payload",
            &session_dir,
            b"renamed",
            planning(),
            &r.cancellation,
        ),
        "unlink-alias" => s.unlink_file(&[], b"alias", 946684800, planning(), &r.cancellation),
        "return-tree" => s.rename(
            &right,
            b"tree-moved",
            &left,
            b"tree",
            planning(),
            &r.cancellation,
        ),
        "return-payload" => s.rename(
            &session_dir,
            b"renamed",
            &[],
            b"payload",
            planning(),
            &r.cancellation,
        ),
        "rmdir-session" => s.remove_directory(
            &right,
            b"session-dir",
            946684800,
            planning(),
            &r.cancellation,
        ),
        _ => panic!("unknown v4 namespace operation"),
    }
}
fn namespace_v4_path_contents(
    s: &crate::fs_ext::ExtJournalSession<Model>,
    path: &[&[u8]],
    expected: &[u8],
    r: &Resources,
) {
    let names: Vec<_> = path.iter().map(|p| NativeName::Bytes(p.to_vec())).collect();
    let file = s.file_at(&names, &r.cancellation).unwrap();
    let mut bytes = vec![0; expected.len() + 1];
    let n = s.read_at(&file, 0, &mut bytes, &r.cancellation).unwrap();
    bytes.truncate(n);
    assert_eq!(bytes, expected);
}
#[expect(
    clippy::too_many_arguments,
    reason = "native verifier compares four independent complete corpus payloads"
)]
fn namespace_v4_contents(
    s: &crate::fs_ext::ExtJournalSession<Model>,
    op: &str,
    is_new: bool,
    payload: &[u8],
    unrelated: &[u8],
    leaf: &[u8],
    indirect: &[u8],
    r: &Resources,
) {
    namespace_v4_path_contents(s, &[b"payload"], payload, r);
    namespace_v4_path_contents(s, &[b"unrelated"], unrelated, r);
    namespace_v4_path_contents(s, &[b"alias"], unrelated, r);
    let tree: &[&[u8]] = if is_new && op == "move-directory" {
        &[b"right", b"tree-moved", b"leaf"]
    } else {
        &[b"left", b"tree", b"leaf"]
    };
    namespace_v4_path_contents(s, tree, leaf, r);
    if is_new && op == "unlink-indirect" {
        assert!(s.file_at(&names(b"indirect"), &r.cancellation).is_err());
    } else {
        namespace_v4_path_contents(s, &[b"indirect"], indirect, r);
    }
}
#[test]
#[ignore = "requires pinned e2fsprogs corpus, fresh namespace evidence and independent native verification"]
fn native_owned_ext3_ordered_namespace_v4_cuts() {
    let corpus = required("PARTMGR_EXT_NAMESPACE_V4_CORPUS");
    let root = required("PARTMGR_GATE_SOURCE_ROOT");
    let out = required("PARTMGR_EXT_NAMESPACE_V4_EVIDENCE");
    fs::create_dir(&out).unwrap();
    fs::create_dir(out.join("images")).unwrap();
    let receipt = checked(
        &corpus.join("receipt.json"),
        "99698f8c91d1bd6215104a7d235b0ba38ff6eb7803ac895330cf46b1d6ebc98c",
    );
    fs::write(out.join("fixture-receipt.json"), receipt).unwrap();
    let models = checked(
        &corpus.join("models.tsv"),
        "0c5709b689af7d978468938764bf43bfcab64e0e8270e7f3836c9da6be7344e5",
    );
    let snapshot = || {
        let mut manifest = String::new();
        for (name, bytes) in compiled_sources() {
            assert_eq!(fs::read(root.join(name)).unwrap(), *bytes);
            writeln!(manifest, "{}  {name}", hash(bytes)).unwrap();
        }
        manifest
    };
    let before = snapshot();
    fs::write(out.join("source-start.sha256"), &before).unwrap();
    for (name, bytes) in compiled_sources() {
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fs::write(
        out.join("gate-binary"),
        fs::read(std::env::current_exe().unwrap()).unwrap(),
    )
    .unwrap();
    let mut manifest = String::from(
        "bs\toperation\tcase\tevent\tmodel\tfault_kind\tprefix\tpre_sha256\tpre_path\tretried_sha256\tretried_path\tresult\n",
    );
    let mut observations = String::new();
    let mut errors = String::new();
    let mut total = 0usize;
    for line in std::str::from_utf8(&models).unwrap().lines() {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 18);
        let bs: usize = f[0].parse().unwrap();
        let original = checked(&corpus.join(f[1]), f[2]);
        let payload = checked(&corpus.join(f[3]), f[4]);
        let unrelated = checked(&corpus.join(f[9]), f[10]);
        let leaf = checked(&corpus.join(f[12]), f[13]);
        let indirect = checked(&corpus.join(f[14]), f[15]);
        let r = resources();
        let boot =
            bootstrap::Bootstrap::read(&Model::new(&original), 65536, 32_000_000, &r).unwrap();
        let journal = boot.physical_blocks.clone();
        drop(boot);
        assert_eq!(r.memory.used(), 0);
        fs::write(
            out.join(format!("journal-map-b{bs}.tsv")),
            journal.iter().map(|n| format!("{n}\n")).collect::<String>(),
        )
        .unwrap();
        for operation in ["move-directory", "unlink-indirect"] {
            let r = resources();
            let mut baseline =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            namespace_v4_operation(&mut baseline, operation, &r).unwrap();
            namespace_v4_contents(
                &baseline, operation, true, &payload, &unrelated, &leaf, &indirect, &r,
            );
            let (baseline, state) = baseline.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            assert_eq!(baseline.visible, baseline.durable);
            let trace = baseline.trace.clone();
            let expected = baseline.visible;
            assert!(!home_equal(&original, &expected, bs, &journal));
            let (h, path) = saved(&out, &expected);
            writeln!(
                observations,
                "bs={bs} operation={operation} events={} baseline={path}",
                trace.len()
            )
            .unwrap();
            assert_eq!(path, format!("images/{h}.raw"));
            let mut events = String::from("event\tkind\tbytes\n");
            for (i, event) in trace.iter().enumerate() {
                match event {
                    Event::Write(n) => writeln!(events, "{}\twrite\t{n}", i + 1).unwrap(),
                    Event::Flush => writeln!(events, "{}\tflush\t0", i + 1).unwrap(),
                }
            }
            fs::write(out.join(format!("events-b{bs}-{operation}.tsv")), events).unwrap();
            assert_eq!(r.memory.used(), 0);
            let mut case = 0usize;
            for (event, kind) in trace.iter().enumerate() {
                let prefixes = match kind {
                    Event::Write(n) => vec![0, n / 2, *n],
                    Event::Flush => vec![0],
                };
                for immediate in [false, true] {
                    for persist in [false, true] {
                        for prefix in &prefixes {
                            case += 1;
                            total += 1;
                            let r = resources();
                            let mut model = Model::new(&original);
                            model.cut = event + 1;
                            model.prefix = *prefix;
                            model.immediate = immediate;
                            model.persist = persist;
                            let mut owner =
                                crate::fs_ext::ExtJournalSession::open(model, public_limits(), &r)
                                    .unwrap();
                            let error =
                                namespace_v4_operation(&mut owner, operation, &r).unwrap_err();
                            writeln!(
                                errors,
                                "bs={bs} operation={operation} case={case} error={error:?}"
                            )
                            .unwrap();
                            assert!(error.to_string().contains("owned native cut"));
                            let (model, state) = owner.into_storage();
                            assert!(model.hit);
                            assert_eq!(state, crate::fs_ext::ExtJournalState::NeedsRecovery);
                            let (prehash, prepath) = saved(&out, &model.durable);
                            let mut cold = crate::fs_ext::ExtJournalSession::open_for_recovery(
                                Model::new(&model.durable),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            cold.recover(&r.cancellation).unwrap();
                            let (recovered, state) = cold.into_storage();
                            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
                            assert_eq!(recovered.visible, recovered.durable);
                            let old = home_equal(&recovered.visible, &original, bs, &journal);
                            let new = home_equal(&recovered.visible, &expected, bs, &journal);
                            assert_ne!(
                                old,
                                new,
                                "namespace partial outcome {bs} {operation} event={} prefix={prefix}",
                                event + 1
                            );
                            let result = if old { "old" } else { "new" };
                            let check = crate::fs_ext::ExtJournalSession::open(
                                Model::new(&recovered.visible),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            namespace_v4_contents(
                                &check, operation, new, &payload, &unrelated, &leaf, &indirect, &r,
                            );
                            drop(check);
                            let (retryhash, retrypath) = saved(&out, &recovered.visible);
                            writeln!(manifest,"{bs}\t{operation}\t{case}\t{}\t{}\t{}\t{prefix}\t{prehash}\t{prepath}\t{retryhash}\t{retrypath}\t{result}",event+1,if immediate{"immediate"}else{"volatile"},match kind{Event::Write(_)=>"write",Event::Flush=>if persist{"flush-persist"}else{"flush-none"}}).unwrap();
                            assert_eq!(r.memory.used(), 0);
                        }
                    }
                }
            }
        }
        let r = resources();
        let persisted = Rc::new(RefCell::new(original.clone()));
        let mut model = Model::new(&original);
        model.snapshot = Some(persisted.clone());
        let mut repeat =
            crate::fs_ext::ExtJournalSession::open(model, public_limits(), &r).unwrap();
        let mut steps = String::from("step\timage_sha256\timage_path\n");
        for (index, step) in [
            "mkdir-session",
            "move-tree",
            "move-payload",
            "rename-payload",
            "unlink-alias",
            "unlink-indirect",
            "return-tree",
            "return-payload",
            "rmdir-session",
        ]
        .iter()
        .enumerate()
        {
            namespace_v4_operation(&mut repeat, step, &r).unwrap();
            let tree_moved = (1..6).contains(&index);
            namespace_v4_path_contents(
                &repeat,
                if tree_moved {
                    &[b"right", b"tree-moved", b"leaf"]
                } else {
                    &[b"left", b"tree", b"leaf"]
                },
                &leaf,
                &r,
            );
            let payload_path: &[&[u8]] = if (2..7).contains(&index) {
                if index == 2 {
                    &[b"right", b"session-dir", b"payload"]
                } else {
                    &[b"right", b"session-dir", b"renamed"]
                }
            } else {
                &[b"payload"]
            };
            namespace_v4_path_contents(&repeat, payload_path, &payload, &r);
            namespace_v4_path_contents(&repeat, &[b"unrelated"], &unrelated, &r);
            if index < 4 {
                namespace_v4_path_contents(&repeat, &[b"alias"], &unrelated, &r);
            } else {
                assert!(repeat.file_at(&names(b"alias"), &r.cancellation).is_err());
            }
            if index < 5 {
                namespace_v4_path_contents(&repeat, &[b"indirect"], &indirect, &r);
            } else {
                assert!(
                    repeat
                        .file_at(&names(b"indirect"), &r.cancellation)
                        .is_err()
                );
            }
            let snapshot = persisted.borrow();
            let (h, path) = saved(&out, &snapshot);
            writeln!(steps, "{step}\t{h}\t{path}").unwrap();
        }
        fs::write(out.join(format!("repeat-v4-b{bs}.tsv")), steps).unwrap();
        let (repeated, state) = repeat.into_storage();
        assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
        assert_eq!(repeated.visible, repeated.durable);
        assert_eq!(repeated.visible, *persisted.borrow());
        drop(repeated);
        assert_eq!(r.memory.used(), 0);
        for (path, digest) in [
            (f[1], f[2]),
            (f[3], f[4]),
            (f[9], f[10]),
            (f[12], f[13]),
            (f[14], f[15]),
        ] {
            checked(&corpus.join(path), digest);
        }
    }
    assert_eq!(snapshot(), before);
    fs::write(out.join("source-end.sha256"), snapshot()).unwrap();
    fs::write(out.join("namespace-cuts.tsv"), manifest).unwrap();
    fs::write(out.join("observations.txt"), observations).unwrap();
    fs::write(out.join("cut-errors.txt"), errors).unwrap();
    checked(
        &corpus.join("receipt.json"),
        "99698f8c91d1bd6215104a7d235b0ba38ff6eb7803ac895330cf46b1d6ebc98c",
    );
    checked(
        &corpus.join("models.tsv"),
        "0c5709b689af7d978468938764bf43bfcab64e0e8270e7f3836c9da6be7344e5",
    );
    fs::write(out.join("report.txt"),format!("complete=true\ncases={total}\nscope=public ordered namespace modeled cuts, exact OLD/NEW homes; independent native verification required; offline modeled qualification only; no kernel or hardware crash claim\n")).unwrap();
}

fn directory_growth_target() -> Vec<u8> {
    let mut name = b"target-".to_vec();
    name.resize(255, b'z');
    name
}
fn directory_growth_operation(
    s: &mut crate::fs_ext::ExtJournalSession<Model>,
    r: &Resources,
) -> io::Result<()> {
    s.rename(
        &[],
        b"payload",
        &names(b"crowded"),
        &directory_growth_target(),
        planning(),
        &r.cancellation,
    )
}
type GrowthPayload = (Vec<&'static [u8]>, String, String, Vec<u8>);
fn directory_growth_contents(
    s: &crate::fs_ext::ExtJournalSession<Model>,
    is_new: bool,
    payloads: &[GrowthPayload],
    r: &Resources,
) {
    for (original_path, _, _, bytes) in payloads {
        if is_new && original_path.as_slice() == [b"payload".as_slice()] {
            let target = directory_growth_target();
            namespace_v4_path_contents(s, &[b"crowded", &target], bytes, r);
            assert!(s.file_at(&names(b"payload"), &r.cancellation).is_err());
        } else {
            namespace_v4_path_contents(s, original_path, bytes, r);
        }
    }
}
#[test]
#[ignore = "requires pinned e2fsprogs corpus, fresh namespace evidence and independent native verification"]
fn native_owned_ext3_ordered_directory_growth_cuts() {
    let corpus = required("PARTMGR_EXT_DIRECTORY_GROWTH_CORPUS");
    let root = required("PARTMGR_GATE_SOURCE_ROOT");
    let out = required("PARTMGR_EXT_DIRECTORY_GROWTH_EVIDENCE");
    fs::create_dir(&out).unwrap();
    fs::create_dir(out.join("images")).unwrap();
    let receipt = checked(
        &corpus.join("receipt.json"),
        "4270bb2d4a715fe39ff9836d8938bc26558ca5ef5facac30eed6801000519a75",
    );
    fs::write(out.join("fixture-receipt.json"), receipt).unwrap();
    let models = checked(
        &corpus.join("models.tsv"),
        "19eca16c3b1c28c6e8d4ddeafa04b09249bd653e5bf05487c0fc12cbb9f8d5b9",
    );
    let snapshot = || {
        let mut manifest = String::new();
        for (name, bytes) in compiled_sources() {
            assert_eq!(fs::read(root.join(name)).unwrap(), *bytes);
            writeln!(manifest, "{}  {name}", hash(bytes)).unwrap();
        }
        manifest
    };
    let before = snapshot();
    fs::write(out.join("source-start.sha256"), &before).unwrap();
    for (name, bytes) in compiled_sources() {
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fs::write(
        out.join("gate-binary"),
        fs::read(std::env::current_exe().unwrap()).unwrap(),
    )
    .unwrap();
    let mut manifest = String::from(
        "bs\toperation\tcase\tevent\tmodel\tfault_kind\tprefix\tpre_sha256\tpre_path\tretried_sha256\tretried_path\tresult\n",
    );
    let mut observations = String::new();
    let mut errors = String::new();
    let mut total = 0usize;
    for line in std::str::from_utf8(&models).unwrap().lines() {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 9);
        let bs: usize = f[0].parse().unwrap();
        let variant = f[1];
        assert!(matches!(variant, "direct" | "indirect"));
        let original = checked(&corpus.join(f[2]), f[3]);
        let crowded_inode: u32 = f[4].parse().unwrap();
        let packing = checked(&corpus.join(f[5]), f[6]);
        fs::write(out.join(format!("packing-b{bs}-{variant}.json")), packing).unwrap();
        checked(&corpus.join(f[7]), f[8]);
        let mut payloads: Vec<GrowthPayload> = Vec::new();
        for (path, suffix) in [
            (vec![b"payload".as_slice()], "payload"),
            (vec![b"unrelated".as_slice()], "unrelated"),
            (vec![b"alias".as_slice()], "alias"),
            (
                vec![b"left".as_slice(), b"tree".as_slice(), b"leaf".as_slice()],
                "left-tree-leaf",
            ),
            (vec![b"indirect".as_slice()], "indirect"),
        ] {
            let filename = format!("dump-b{bs}-{variant}-{suffix}.bin");
            let bytes = fs::read(corpus.join(&filename)).unwrap();
            payloads.push((path, filename, hash(&bytes), bytes));
        }
        let r = resources();
        let boot =
            bootstrap::Bootstrap::read(&Model::new(&original), 65536, 32_000_000, &r).unwrap();
        let journal = boot.physical_blocks.clone();
        drop(boot);
        assert_eq!(r.memory.used(), 0);
        fs::write(
            out.join(format!("journal-map-b{bs}.tsv")),
            journal.iter().map(|n| format!("{n}\n")).collect::<String>(),
        )
        .unwrap();
        {
            let operation = if variant == "direct" {
                "move-grow-direct"
            } else {
                "move-grow-indirect"
            };
            let r = resources();
            let mut baseline =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            directory_growth_contents(&baseline, false, &payloads, &r);
            directory_growth_operation(&mut baseline, &r).unwrap();
            directory_growth_contents(&baseline, true, &payloads, &r);
            let (baseline, state) = baseline.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            assert_eq!(baseline.visible, baseline.durable);
            let trace = baseline.trace.clone();
            let expected = baseline.visible;
            assert!(!home_equal(&original, &expected, bs, &journal));
            let expected_source = Model::new(&expected);
            let (decoder, proof) =
                super::super::ExtDecoder::open_native_clean(&expected_source, 91, &r).unwrap();
            let inode = decoder.inode(crowded_inode, &r).unwrap();
            assert_eq!(
                inode.len(),
                ((if variant == "direct" { 2 } else { 13 }) * bs) as u64
            );
            assert_eq!(
                super::super::u32le(inode.raw_metadata(), 88) != 0,
                variant == "indirect"
            );
            drop((inode, decoder, proof));

            let (h, path) = saved(&out, &expected);
            writeln!(
                observations,
                "bs={bs} operation={operation} events={} baseline={path}",
                trace.len()
            )
            .unwrap();
            assert_eq!(path, format!("images/{h}.raw"));
            let mut events = String::from("event\tkind\tbytes\n");
            for (i, event) in trace.iter().enumerate() {
                match event {
                    Event::Write(n) => writeln!(events, "{}\twrite\t{n}", i + 1).unwrap(),
                    Event::Flush => writeln!(events, "{}\tflush\t0", i + 1).unwrap(),
                }
            }
            fs::write(out.join(format!("events-b{bs}-{operation}.tsv")), events).unwrap();
            assert_eq!(r.memory.used(), 0);
            let mut case = 0usize;
            for (event, kind) in trace.iter().enumerate() {
                let prefixes = match kind {
                    Event::Write(n) => vec![0, n / 2, *n],
                    Event::Flush => vec![0],
                };
                for immediate in [false, true] {
                    for persist in [false, true] {
                        for prefix in &prefixes {
                            case += 1;
                            total += 1;
                            let r = resources();
                            let mut model = Model::new(&original);
                            model.cut = event + 1;
                            model.prefix = *prefix;
                            model.immediate = immediate;
                            model.persist = persist;
                            let mut owner =
                                crate::fs_ext::ExtJournalSession::open(model, public_limits(), &r)
                                    .unwrap();
                            let error = directory_growth_operation(&mut owner, &r).unwrap_err();
                            writeln!(
                                errors,
                                "bs={bs} operation={operation} case={case} error={error:?}"
                            )
                            .unwrap();
                            assert!(error.to_string().contains("owned native cut"));
                            let (model, state) = owner.into_storage();
                            assert!(model.hit);
                            assert_eq!(state, crate::fs_ext::ExtJournalState::NeedsRecovery);
                            let (prehash, prepath) = saved(&out, &model.durable);
                            let mut cold = crate::fs_ext::ExtJournalSession::open_for_recovery(
                                Model::new(&model.durable),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            cold.recover(&r.cancellation).unwrap();
                            let (recovered, state) = cold.into_storage();
                            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
                            assert_eq!(recovered.visible, recovered.durable);
                            let old = home_equal(&recovered.visible, &original, bs, &journal);
                            let new = home_equal(&recovered.visible, &expected, bs, &journal);
                            assert_ne!(
                                old,
                                new,
                                "namespace partial outcome {bs} {operation} event={} prefix={prefix}",
                                event + 1
                            );
                            let result = if old { "old" } else { "new" };
                            let check = crate::fs_ext::ExtJournalSession::open(
                                Model::new(&recovered.visible),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            directory_growth_contents(&check, new, &payloads, &r);
                            drop(check);
                            let (retryhash, retrypath) = saved(&out, &recovered.visible);
                            writeln!(manifest,"{bs}\t{operation}\t{case}\t{}\t{}\t{}\t{prefix}\t{prehash}\t{prepath}\t{retryhash}\t{retrypath}\t{result}",event+1,if immediate{"immediate"}else{"volatile"},match kind{Event::Write(_)=>"write",Event::Flush=>if persist{"flush-persist"}else{"flush-none"}}).unwrap();
                            assert_eq!(r.memory.used(), 0);
                        }
                    }
                }
            }
        }
        checked(&corpus.join(f[2]), f[3]);
        checked(&corpus.join(f[5]), f[6]);
        checked(&corpus.join(f[7]), f[8]);
        for (_, filename, digest, _) in &payloads {
            checked(&corpus.join(filename), digest);
        }
    }
    assert_eq!(snapshot(), before);
    fs::write(out.join("source-end.sha256"), snapshot()).unwrap();
    fs::write(out.join("namespace-cuts.tsv"), manifest).unwrap();
    fs::write(out.join("observations.txt"), observations).unwrap();
    fs::write(out.join("cut-errors.txt"), errors).unwrap();
    checked(
        &corpus.join("receipt.json"),
        "4270bb2d4a715fe39ff9836d8938bc26558ca5ef5facac30eed6801000519a75",
    );
    checked(
        &corpus.join("models.tsv"),
        "19eca16c3b1c28c6e8d4ddeafa04b09249bd653e5bf05487c0fc12cbb9f8d5b9",
    );
    fs::write(out.join("report.txt"),format!("complete=true\ncases={total}\nscope=public forced directory growth modeled cuts, exact OLD/NEW homes; independent native verification required; offline modeled qualification only; no kernel or hardware crash claim\n")).unwrap();
}

fn truncate_native_operation(
    s: &mut crate::fs_ext::ExtJournalSession<Model>,
    name: &[u8],
    length: u64,
    r: &Resources,
) -> io::Result<()> {
    let file = s.file_at(&names(name), &r.cancellation)?;
    s.truncate(&file, length, planning(), &r.cancellation)
}
#[test]
#[ignore = "requires pinned e2fsprogs corpus, fresh namespace evidence and independent native verification"]
fn native_owned_ext3_ordered_truncate_cuts() {
    let corpus = required("PARTMGR_EXT_TRUNCATE_CORPUS");
    let root = required("PARTMGR_GATE_SOURCE_ROOT");
    let out = required("PARTMGR_EXT_TRUNCATE_EVIDENCE");
    fs::create_dir(&out).unwrap();
    fs::create_dir(out.join("images")).unwrap();
    let receipt = checked(
        &corpus.join("receipt.json"),
        "368ce6dae4ad3a375818de3e21e861e3a6596c15f115fb2fee117c4ea6351ec5",
    );
    fs::write(out.join("fixture-receipt.json"), receipt).unwrap();
    let models = checked(
        &corpus.join("cases.tsv"),
        "4c099bca8b93695750e54d3d993006d1ba1796ad53c22170fe472fc35f9cd8bb",
    );
    let snapshot = || {
        let mut manifest = String::new();
        for (name, bytes) in compiled_sources() {
            assert_eq!(fs::read(root.join(name)).unwrap(), *bytes);
            writeln!(manifest, "{}  {name}", hash(bytes)).unwrap();
        }
        manifest
    };
    let before = snapshot();
    fs::write(out.join("source-start.sha256"), &before).unwrap();
    for (name, bytes) in compiled_sources() {
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fs::write(
        out.join("gate-binary"),
        fs::read(std::env::current_exe().unwrap()).unwrap(),
    )
    .unwrap();
    let mut manifest = String::from(
        "bs\toperation\tcase\tevent\tmodel\tfault_kind\tprefix\tpre_sha256\tpre_path\tretried_sha256\tretried_path\tresult\n",
    );
    let mut enospc = String::from("bs\tsource_sha256\tafter_sha256\twrites\tflushes\terror\n");
    let mut observations = String::new();
    let mut errors = String::new();
    let mut total = 0usize;
    for line in std::str::from_utf8(&models).unwrap().lines() {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 11);
        let bs: usize = f[0].parse().unwrap();
        let variant = f[1];
        let original = checked(&corpus.join(f[2]), f[3]);
        let source_name = f[4].strip_prefix('/').unwrap().as_bytes();
        let inode_number: u32 = f[5].parse().unwrap();
        let old_length: usize = f[6].parse().unwrap();
        let new_length: usize = f[7].parse().unwrap();
        let payload = checked(&corpus.join(f[8]), f[9]);
        assert_eq!(payload.len(), old_length);
        let alias = f[10].strip_prefix('/').unwrap().as_bytes();
        let operation = format!("truncate-{variant}");
        if variant == "enospc" {
            let r = resources();
            let mut owner =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            let file = owner.file_at(&names(source_name), &r.cancellation).unwrap();
            let error = owner
                .truncate(&file, new_length as u64, planning(), &r.cancellation)
                .unwrap_err();
            assert!(format!("{error:?}").contains("InvalidOperation"));
            assert!(
                error
                    .to_string()
                    .contains("ext2 no audited free blocks available")
            );
            drop(file);
            let (model, state) = owner.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            assert!(model.trace.is_empty());
            assert_eq!(model.visible, original);
            assert_eq!(model.durable, original);
            writeln!(
                enospc,
                "{bs}\t{}\t{}\t0\t0\tInvalidOperation:no-audited-free-blocks",
                hash(&original),
                hash(&model.visible)
            )
            .unwrap();
            assert_eq!(r.memory.used(), 0);
            checked(&corpus.join(f[2]), f[3]);
            checked(&corpus.join(f[8]), f[9]);
            continue;
        }
        let r = resources();
        let boot =
            bootstrap::Bootstrap::read(&Model::new(&original), 65536, 32_000_000, &r).unwrap();
        let journal = boot.physical_blocks.clone();
        drop(boot);
        assert_eq!(r.memory.used(), 0);
        fs::write(
            out.join(format!("journal-map-b{bs}.tsv")),
            journal.iter().map(|n| format!("{n}\n")).collect::<String>(),
        )
        .unwrap();
        {
            let r = resources();
            let mut baseline =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            for path in [source_name, alias] {
                namespace_v4_path_contents(&baseline, &[path], &payload, &r);
            }
            truncate_native_operation(&mut baseline, source_name, new_length as u64, &r).unwrap();
            for path in [source_name, alias] {
                namespace_v4_path_contents(&baseline, &[path], &payload[..new_length], &r);
            }
            let (baseline, state) = baseline.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            assert_eq!(baseline.visible, baseline.durable);
            let trace = baseline.trace.clone();
            let expected = baseline.visible;
            let mut old_mask = journal.clone();
            if matches!(variant, "partial-direct" | "partial-indirect") {
                let original_source = Model::new(&original);
                let expected_source = Model::new(&expected);
                let (before_decoder, before_proof) =
                    super::super::ExtDecoder::open_native_clean(&original_source, 91, &r).unwrap();
                let (after_decoder, after_proof) =
                    super::super::ExtDecoder::open_native_clean(&expected_source, 92, &r).unwrap();
                let before_map = before_decoder
                    .file_map(inode_number, 65536, &r, false)
                    .unwrap();
                let after_map = after_decoder
                    .file_map(inode_number, 65536, &r, false)
                    .unwrap();
                let logical = (new_length / bs * bs) as u64;
                let physical = |map: &crate::fs_ext::ExtDecodedFileMap| {
                    let extent = map
                        .extents
                        .iter()
                        .find(|extent| {
                            extent.offset <= logical && logical < extent.offset + extent.length
                        })
                        .unwrap();
                    match extent.kind {
                        crate::fs_file::ExtentKind::Data(at) => {
                            ((at + logical - extent.offset) / bs as u64) as u32
                        }
                        _ => panic!("mapped COW tail required"),
                    }
                };
                let old_block = physical(&before_map);
                let fresh = physical(&after_map);
                assert_ne!(old_block, fresh);
                let g = before_decoder.geometry();
                let group = (fresh - g.first) / g.blocks_per_group;
                let bit = ((fresh - g.first) % g.blocks_per_group) as usize;
                let bitmap = before_decoder.group(group).unwrap()[0] as usize * bs;
                assert_eq!(original[bitmap + bit / 8] & (1 << (bit % 8)), 0);
                assert!(!journal.contains(&fresh));
                let prefix = new_length % bs;
                let old_at = old_block as usize * bs;
                let fresh_at = fresh as usize * bs;
                assert_eq!(
                    &expected[fresh_at..fresh_at + prefix],
                    &original[old_at..old_at + prefix]
                );
                assert!(
                    expected[fresh_at + prefix..fresh_at + bs]
                        .iter()
                        .all(|b| *b == 0)
                );
                assert_eq!(
                    &original[old_at..old_at + bs],
                    &expected[old_at..old_at + bs]
                );
                old_mask.push(fresh);
                fs::write(
                    out.join(format!("cow-b{bs}-{operation}.tsv")),
                    format!("source_block\tfresh_block\tprefix\n{old_block}\t{fresh}\t{prefix}\n"),
                )
                .unwrap();
                drop((
                    before_map,
                    after_map,
                    before_decoder,
                    after_decoder,
                    before_proof,
                    after_proof,
                ));
            }
            let (h, path) = saved(&out, &expected);
            writeln!(
                observations,
                "bs={bs} operation={operation} events={} baseline={path}",
                trace.len()
            )
            .unwrap();
            assert_eq!(path, format!("images/{h}.raw"));
            let mut events = String::from("event\tkind\tbytes\n");
            for (i, event) in trace.iter().enumerate() {
                match event {
                    Event::Write(n) => writeln!(events, "{}\twrite\t{n}", i + 1).unwrap(),
                    Event::Flush => writeln!(events, "{}\tflush\t0", i + 1).unwrap(),
                }
            }
            fs::write(out.join(format!("events-b{bs}-{operation}.tsv")), events).unwrap();
            assert_eq!(r.memory.used(), 0);
            let mut case = 0usize;
            for (event, kind) in trace.iter().enumerate() {
                let prefixes = match kind {
                    Event::Write(n) => vec![0, n / 2, *n],
                    Event::Flush => vec![0],
                };
                for immediate in [false, true] {
                    for persist in [false, true] {
                        for prefix in &prefixes {
                            case += 1;
                            total += 1;
                            let r = resources();
                            let mut model = Model::new(&original);
                            model.cut = event + 1;
                            model.prefix = *prefix;
                            model.immediate = immediate;
                            model.persist = persist;
                            let mut owner =
                                crate::fs_ext::ExtJournalSession::open(model, public_limits(), &r)
                                    .unwrap();
                            let error = truncate_native_operation(
                                &mut owner,
                                source_name,
                                new_length as u64,
                                &r,
                            )
                            .unwrap_err();
                            writeln!(
                                errors,
                                "bs={bs} operation={operation} case={case} error={error:?}"
                            )
                            .unwrap();
                            assert!(error.to_string().contains("owned native cut"));
                            let (model, state) = owner.into_storage();
                            assert!(model.hit);
                            assert_eq!(state, crate::fs_ext::ExtJournalState::NeedsRecovery);
                            let (prehash, prepath) = saved(&out, &model.durable);
                            let mut cold = crate::fs_ext::ExtJournalSession::open_for_recovery(
                                Model::new(&model.durable),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            cold.recover(&r.cancellation).unwrap();
                            let (recovered, state) = cold.into_storage();
                            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
                            assert_eq!(recovered.visible, recovered.durable);
                            let old = home_equal(&recovered.visible, &original, bs, &old_mask);
                            let new = home_equal(&recovered.visible, &expected, bs, &journal);
                            assert_ne!(
                                old,
                                new,
                                "namespace partial outcome {bs} {operation} event={} prefix={prefix}",
                                event + 1
                            );
                            let result = if old { "old" } else { "new" };
                            let check = crate::fs_ext::ExtJournalSession::open(
                                Model::new(&recovered.visible),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            for path in [source_name, alias] {
                                namespace_v4_path_contents(
                                    &check,
                                    &[path],
                                    if new {
                                        &payload[..new_length]
                                    } else {
                                        &payload
                                    },
                                    &r,
                                );
                            }
                            drop(check);
                            let (retryhash, retrypath) = saved(&out, &recovered.visible);
                            writeln!(manifest,"{bs}\t{operation}\t{case}\t{}\t{}\t{}\t{prefix}\t{prehash}\t{prepath}\t{retryhash}\t{retrypath}\t{result}",event+1,if immediate{"immediate"}else{"volatile"},match kind{Event::Write(_)=>"write",Event::Flush=>if persist{"flush-persist"}else{"flush-none"}}).unwrap();
                            assert_eq!(r.memory.used(), 0);
                        }
                    }
                }
            }
        }
        checked(&corpus.join(f[2]), f[3]);
        checked(&corpus.join(f[8]), f[9]);
    }
    assert_eq!(snapshot(), before);
    fs::write(out.join("source-end.sha256"), snapshot()).unwrap();
    fs::write(out.join("namespace-cuts.tsv"), manifest).unwrap();
    fs::write(out.join("observations.txt"), observations).unwrap();
    fs::write(out.join("cut-errors.txt"), errors).unwrap();
    fs::write(out.join("enospc.tsv"), enospc).unwrap();
    checked(
        &corpus.join("receipt.json"),
        "368ce6dae4ad3a375818de3e21e861e3a6596c15f115fb2fee117c4ea6351ec5",
    );
    checked(
        &corpus.join("cases.tsv"),
        "4c099bca8b93695750e54d3d993006d1ba1796ad53c22170fe472fc35f9cd8bb",
    );
    fs::write(out.join("report.txt"),format!("complete=true\ncases={total}\nscope=public classic truncate modeled cuts, exact OLD/NEW homes; independent native verification required; offline modeled qualification only; no kernel or hardware crash claim\n")).unwrap();
}

fn hex_bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}
#[test]
#[ignore = "requires pinned e2fsprogs corpus, fresh namespace evidence and independent native verification"]
fn native_owned_ext3_ordered_hardlink_cuts() {
    let corpus = required("PARTMGR_EXT_HARDLINK_CORPUS");
    let root = required("PARTMGR_GATE_SOURCE_ROOT");
    let out = required("PARTMGR_EXT_HARDLINK_EVIDENCE");
    fs::create_dir(&out).unwrap();
    fs::create_dir(out.join("images")).unwrap();
    let receipt = checked(
        &corpus.join("receipt.json"),
        "592b0c71a9dc43b1bdb98549955a9a9f98741988dd6d098981f20a509ecd4256",
    );
    fs::write(out.join("fixture-receipt.json"), receipt).unwrap();
    let models = checked(
        &corpus.join("models.tsv"),
        "257fa75b7055632bcfcf858d3a017394d087a642fd028169353603b4a1e5c54e",
    );
    let snapshot = || {
        let mut manifest = String::new();
        for (name, bytes) in compiled_sources() {
            assert_eq!(fs::read(root.join(name)).unwrap(), *bytes);
            writeln!(manifest, "{}  {name}", hash(bytes)).unwrap();
        }
        manifest
    };
    let before = snapshot();
    fs::write(out.join("source-start.sha256"), &before).unwrap();
    for (name, bytes) in compiled_sources() {
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fs::write(
        out.join("gate-binary"),
        fs::read(std::env::current_exe().unwrap()).unwrap(),
    )
    .unwrap();
    let mut manifest = String::from(
        "bs\toperation\tcase\tevent\tmodel\tfault_kind\tprefix\tpre_sha256\tpre_path\tretried_sha256\tretried_path\tresult\n",
    );
    let mut observations = String::new();
    let mut errors = String::new();
    let mut total = 0usize;
    for line in std::str::from_utf8(&models).unwrap().lines() {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 12);
        let bs: usize = f[0].parse().unwrap();
        let operation = f[1];
        assert!(matches!(
            operation,
            "hardlink-same" | "hardlink-cross" | "hardlink-grow-direct" | "hardlink-grow-indirect"
        ));
        let original = checked(&corpus.join(f[2]), f[3]);
        let source_parts: Vec<&[u8]> = f[4]
            .as_bytes()
            .split(|b| *b == b'/')
            .filter(|part| !part.is_empty())
            .collect();
        let destination_parts: Vec<&[u8]> = f[5]
            .as_bytes()
            .split(|b| *b == b'/')
            .filter(|part| !part.is_empty())
            .collect();
        let target = hex_bytes(f[6]);
        let source_inode: u32 = f[7].parse().unwrap();
        checked(&corpus.join(f[8]), f[9]);
        let payload = checked(&corpus.join(f[10]), f[11]);
        let source_parent: Vec<_> = source_parts[..source_parts.len() - 1]
            .iter()
            .map(|part| crate::fs_core::NativeName::Bytes(part.to_vec()))
            .collect();
        let destination_parent: Vec<_> = destination_parts
            .iter()
            .map(|part| crate::fs_core::NativeName::Bytes(part.to_vec()))
            .collect();
        let source_name = source_parts.last().unwrap();
        let mutate = |owner: &mut crate::fs_ext::ExtJournalSession<Model>, r: &Resources| {
            owner.hard_link(
                &source_parent,
                source_name,
                &destination_parent,
                &target,
                planning(),
                &r.cancellation,
            )
        };
        let contents =
            |owner: &crate::fs_ext::ExtJournalSession<Model>, is_new: bool, r: &Resources| {
                namespace_v4_path_contents(owner, &source_parts, &payload, r);
                let mut alias = destination_parts.clone();
                alias.push(&target);
                if is_new {
                    namespace_v4_path_contents(owner, &alias, &payload, r);
                } else {
                    let path: Vec<_> = alias
                        .iter()
                        .map(|part| crate::fs_core::NativeName::Bytes(part.to_vec()))
                        .collect();
                    assert!(owner.file_at(&path, &r.cancellation).is_err());
                }
            };
        let r = resources();
        let boot =
            bootstrap::Bootstrap::read(&Model::new(&original), 65536, 32_000_000, &r).unwrap();
        let journal = boot.physical_blocks.clone();
        drop(boot);
        assert_eq!(r.memory.used(), 0);
        fs::write(
            out.join(format!("journal-map-b{bs}.tsv")),
            journal.iter().map(|n| format!("{n}\n")).collect::<String>(),
        )
        .unwrap();
        {
            let r = resources();
            let mut baseline =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            contents(&baseline, false, &r);
            mutate(&mut baseline, &r).unwrap();
            contents(&baseline, true, &r);
            let (baseline, state) = baseline.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            assert_eq!(baseline.visible, baseline.durable);
            let trace = baseline.trace.clone();
            let expected = baseline.visible;
            assert!(!home_equal(&original, &expected, bs, &journal));
            let expected_source = Model::new(&expected);
            let (decoder, proof) =
                super::super::ExtDecoder::open_native_clean(&expected_source, 91, &r).unwrap();
            let inode = decoder.inode(source_inode, &r).unwrap();
            let old_source = Model::new(&original);
            let (old_decoder, old_proof) =
                super::super::ExtDecoder::open_native_clean(&old_source, 92, &r).unwrap();
            let old_inode = old_decoder.inode(source_inode, &r).unwrap();
            let mut old_raw = old_inode.raw_metadata().to_vec();
            let old_links = super::super::u16le(&old_raw, 26);
            old_raw[26..28].copy_from_slice(&(old_links + 1).to_le_bytes());
            assert_eq!(inode.raw_metadata().as_slice(), old_raw.as_slice());
            drop((inode, decoder, proof, old_inode, old_decoder, old_proof));

            let (h, path) = saved(&out, &expected);
            writeln!(
                observations,
                "bs={bs} operation={operation} events={} baseline={path}",
                trace.len()
            )
            .unwrap();
            assert_eq!(path, format!("images/{h}.raw"));
            let mut events = String::from("event\tkind\tbytes\n");
            for (i, event) in trace.iter().enumerate() {
                match event {
                    Event::Write(n) => writeln!(events, "{}\twrite\t{n}", i + 1).unwrap(),
                    Event::Flush => writeln!(events, "{}\tflush\t0", i + 1).unwrap(),
                }
            }
            fs::write(out.join(format!("events-b{bs}-{operation}.tsv")), events).unwrap();
            assert_eq!(r.memory.used(), 0);
            let mut case = 0usize;
            for (event, kind) in trace.iter().enumerate() {
                let prefixes = match kind {
                    Event::Write(n) => vec![0, n / 2, *n],
                    Event::Flush => vec![0],
                };
                for immediate in [false, true] {
                    for persist in [false, true] {
                        for prefix in &prefixes {
                            case += 1;
                            total += 1;
                            let r = resources();
                            let mut model = Model::new(&original);
                            model.cut = event + 1;
                            model.prefix = *prefix;
                            model.immediate = immediate;
                            model.persist = persist;
                            let mut owner =
                                crate::fs_ext::ExtJournalSession::open(model, public_limits(), &r)
                                    .unwrap();
                            let error = mutate(&mut owner, &r).unwrap_err();
                            writeln!(
                                errors,
                                "bs={bs} operation={operation} case={case} error={error:?}"
                            )
                            .unwrap();
                            assert!(error.to_string().contains("owned native cut"));
                            let (model, state) = owner.into_storage();
                            assert!(model.hit);
                            assert_eq!(state, crate::fs_ext::ExtJournalState::NeedsRecovery);
                            let (prehash, prepath) = saved(&out, &model.durable);
                            let mut cold = crate::fs_ext::ExtJournalSession::open_for_recovery(
                                Model::new(&model.durable),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            cold.recover(&r.cancellation).unwrap();
                            let (recovered, state) = cold.into_storage();
                            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
                            assert_eq!(recovered.visible, recovered.durable);
                            let old = home_equal(&recovered.visible, &original, bs, &journal);
                            let new = home_equal(&recovered.visible, &expected, bs, &journal);
                            assert_ne!(
                                old,
                                new,
                                "namespace partial outcome {bs} {operation} event={} prefix={prefix}",
                                event + 1
                            );
                            let result = if old { "old" } else { "new" };
                            let check = crate::fs_ext::ExtJournalSession::open(
                                Model::new(&recovered.visible),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            contents(&check, new, &r);
                            drop(check);
                            let (retryhash, retrypath) = saved(&out, &recovered.visible);
                            writeln!(manifest,"{bs}\t{operation}\t{case}\t{}\t{}\t{}\t{prefix}\t{prehash}\t{prepath}\t{retryhash}\t{retrypath}\t{result}",event+1,if immediate{"immediate"}else{"volatile"},match kind{Event::Write(_)=>"write",Event::Flush=>if persist{"flush-persist"}else{"flush-none"}}).unwrap();
                            assert_eq!(r.memory.used(), 0);
                        }
                    }
                }
            }
        }
        checked(&corpus.join(f[2]), f[3]);
        checked(&corpus.join(f[8]), f[9]);
        checked(&corpus.join(f[10]), f[11]);
    }
    assert_eq!(snapshot(), before);
    fs::write(out.join("source-end.sha256"), snapshot()).unwrap();
    fs::write(out.join("namespace-cuts.tsv"), manifest).unwrap();
    fs::write(out.join("observations.txt"), observations).unwrap();
    fs::write(out.join("cut-errors.txt"), errors).unwrap();
    checked(
        &corpus.join("receipt.json"),
        "592b0c71a9dc43b1bdb98549955a9a9f98741988dd6d098981f20a509ecd4256",
    );
    checked(
        &corpus.join("models.tsv"),
        "257fa75b7055632bcfcf858d3a017394d087a642fd028169353603b4a1e5c54e",
    );
    fs::write(out.join("report.txt"),format!("complete=true\ncases={total}\nscope=public regular hardlink modeled cuts, exact OLD/NEW homes; independent native verification required; offline modeled qualification only; no kernel or hardware crash claim\n")).unwrap();
}

fn overwrite_native_operation(
    s: &mut crate::fs_ext::ExtJournalSession<Model>,
    name: &[u8],
    offset: u64,
    input: &dyn FileRead,
    r: &Resources,
) -> io::Result<u64> {
    let file = s.file_at(&names(name), &r.cancellation)?;
    s.write_at(&file, offset, input, planning(), &r.cancellation)
}
#[test]
#[ignore = "requires pinned e2fsprogs corpus, fresh namespace evidence and independent native verification"]
fn native_owned_ext3_ordered_overwrite_cuts() {
    let corpus = required("PARTMGR_EXT_OVERWRITE_CORPUS");
    let root = required("PARTMGR_GATE_SOURCE_ROOT");
    let out = required("PARTMGR_EXT_OVERWRITE_EVIDENCE");
    fs::create_dir(&out).unwrap();
    fs::create_dir(out.join("images")).unwrap();
    let receipt = checked(
        &corpus.join("receipt.json"),
        "c28089d995c623a6cb90d2b32d2255cbccda5d1550801cd6c3325404b3516d61",
    );
    fs::write(out.join("fixture-receipt.json"), receipt).unwrap();
    let models = checked(
        &corpus.join("cases.tsv"),
        "03f67dbe987473994e8ed2c997f6524162d8d961278e7eea16b8100ed5f735fa",
    );
    let snapshot = || {
        let mut manifest = String::new();
        for (name, bytes) in compiled_sources() {
            assert_eq!(fs::read(root.join(name)).unwrap(), *bytes);
            writeln!(manifest, "{}  {name}", hash(bytes)).unwrap();
        }
        manifest
    };
    let before = snapshot();
    fs::write(out.join("source-start.sha256"), &before).unwrap();
    for (name, bytes) in compiled_sources() {
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fs::write(
        out.join("gate-binary"),
        fs::read(std::env::current_exe().unwrap()).unwrap(),
    )
    .unwrap();
    let mut manifest = String::from(
        "bs\toperation\tcase\tevent\tmodel\tfault_kind\tprefix\tpre_sha256\tpre_path\tretried_sha256\tretried_path\tresult\n",
    );
    let mut enospc = String::from("bs\tsource_sha256\tafter_sha256\twrites\tflushes\terror\n");
    let mut observations = String::new();
    let mut errors = String::new();
    let mut total = 0usize;
    for line in std::str::from_utf8(&models).unwrap().lines().skip(1) {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 11);
        let bs: usize = f[0].parse().unwrap();
        let variant = f[1];
        let original = checked(&corpus.join(f[2]), f[3]);
        let source_name = f[4].strip_prefix('/').unwrap().as_bytes();
        let inode_number: u32 = f[5].parse().unwrap();
        let old_length: usize = f[6].parse().unwrap();
        let write_offset: u64 = f[7].parse().unwrap();
        let input = Input {
            bytes: checked(&corpus.join(f[8]), f[9]),
            id: ObjectId {
                source: 79,
                generation: 1,
                native: vec![5],
            },
        };
        let tag = std::str::from_utf8(source_name)
            .unwrap()
            .strip_prefix("truncate-")
            .unwrap();
        let payload_path = corpus.join(format!("payload-b{bs}-{tag}.bin"));
        let payload = fs::read(&payload_path).unwrap();
        let payload_hash = hash(&payload);
        let mut final_payload = payload.clone();
        let range_end = write_offset as usize + input.bytes.len();
        final_payload[write_offset as usize..range_end].copy_from_slice(&input.bytes);
        assert_eq!(payload.len(), old_length);
        let alias = f[10].strip_prefix('/').unwrap().as_bytes();
        let operation = format!("overwrite-{variant}");
        if variant == "enospc" {
            let r = resources();
            let mut owner =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            let file = owner.file_at(&names(source_name), &r.cancellation).unwrap();
            let error = owner
                .write_at(&file, write_offset, &input, planning(), &r.cancellation)
                .unwrap_err();
            assert!(format!("{error:?}").contains("InvalidOperation"));
            assert!(
                error
                    .to_string()
                    .contains("ext2 no audited free blocks available")
            );
            drop(file);
            let (model, state) = owner.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            assert!(model.trace.is_empty());
            assert_eq!(model.visible, original);
            assert_eq!(model.durable, original);
            writeln!(
                enospc,
                "{bs}\t{}\t{}\t0\t0\tInvalidOperation:no-audited-free-blocks",
                hash(&original),
                hash(&model.visible)
            )
            .unwrap();
            assert_eq!(r.memory.used(), 0);
            checked(&corpus.join(f[2]), f[3]);
            checked(&corpus.join(f[8]), f[9]);
            continue;
        }
        let r = resources();
        let boot =
            bootstrap::Bootstrap::read(&Model::new(&original), 65536, 32_000_000, &r).unwrap();
        let journal = boot.physical_blocks.clone();
        drop(boot);
        assert_eq!(r.memory.used(), 0);
        fs::write(
            out.join(format!("journal-map-b{bs}.tsv")),
            journal.iter().map(|n| format!("{n}\n")).collect::<String>(),
        )
        .unwrap();
        {
            let r = resources();
            let mut baseline =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            for path in [source_name, alias] {
                namespace_v4_path_contents(&baseline, &[path], &payload, &r);
            }
            assert_eq!(
                overwrite_native_operation(&mut baseline, source_name, write_offset, &input, &r)
                    .unwrap(),
                input.len()
            );
            for path in [source_name, alias] {
                namespace_v4_path_contents(&baseline, &[path], &final_payload, &r);
            }
            let (baseline, state) = baseline.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            assert_eq!(baseline.visible, baseline.durable);
            let trace = baseline.trace.clone();
            let expected = baseline.visible;
            let mut old_mask = journal.clone();
            {
                let original_source = Model::new(&original);
                let expected_source = Model::new(&expected);
                let (before_decoder, before_proof) =
                    super::super::ExtDecoder::open_native_clean(&original_source, 91, &r).unwrap();
                let (after_decoder, after_proof) =
                    super::super::ExtDecoder::open_native_clean(&expected_source, 92, &r).unwrap();
                let before_map = before_decoder
                    .file_map(inode_number, 65536, &r, false)
                    .unwrap();
                let after_map = after_decoder
                    .file_map(inode_number, 65536, &r, false)
                    .unwrap();
                let physical = |map: &crate::fs_ext::ExtDecodedFileMap, logical: u64| {
                    let extent = map
                        .extents
                        .iter()
                        .find(|extent| {
                            extent.offset <= logical && logical < extent.offset + extent.length
                        })
                        .unwrap();
                    match extent.kind {
                        crate::fs_file::ExtentKind::Data(at) => {
                            Some(((at + logical - extent.offset) / bs as u64) as u32)
                        }
                        crate::fs_file::ExtentKind::Hole => None,
                        _ => panic!("unsupported source extent"),
                    }
                };
                let end = write_offset + input.len();
                let mut cow = String::from("logical_block\tsource_block\tfresh_block\n");
                for logical_block in write_offset / bs as u64..end.div_ceil(bs as u64) {
                    let logical = logical_block * bs as u64;
                    let old_block = physical(&before_map, logical);
                    let fresh = physical(&after_map, logical).unwrap();
                    assert_ne!(old_block, Some(fresh));
                    let g = before_decoder.geometry();
                    let group = (fresh - g.first) / g.blocks_per_group;
                    let bit = ((fresh - g.first) % g.blocks_per_group) as usize;
                    let bitmap = before_decoder.group(group).unwrap()[0] as usize * bs;
                    assert_eq!(original[bitmap + bit / 8] & (1 << (bit % 8)), 0);
                    assert!(!journal.contains(&fresh));
                    let mut body = vec![0; bs];
                    if let Some(old) = old_block {
                        let at = old as usize * bs;
                        body.copy_from_slice(&original[at..at + bs]);
                        assert_eq!(&original[at..at + bs], &expected[at..at + bs]);
                    }
                    let within = write_offset.saturating_sub(logical) as usize;
                    let until = (end - logical).min(bs as u64) as usize;
                    body[within..until].copy_from_slice(
                        &input.bytes[(logical + within as u64 - write_offset) as usize
                            ..(logical + until as u64 - write_offset) as usize],
                    );
                    let at = fresh as usize * bs;
                    assert_eq!(body, expected[at..at + bs]);
                    old_mask.push(fresh);
                    writeln!(cow, "{logical_block}\t{}\t{fresh}", old_block.unwrap_or(0)).unwrap();
                }
                fs::write(out.join(format!("cow-b{bs}-{operation}.tsv")), cow).unwrap();
                drop((
                    before_map,
                    after_map,
                    before_decoder,
                    after_decoder,
                    before_proof,
                    after_proof,
                ));
            }
            let (h, path) = saved(&out, &expected);
            writeln!(
                observations,
                "bs={bs} operation={operation} events={} baseline={path}",
                trace.len()
            )
            .unwrap();
            assert_eq!(path, format!("images/{h}.raw"));
            let mut events = String::from("event\tkind\tbytes\n");
            for (i, event) in trace.iter().enumerate() {
                match event {
                    Event::Write(n) => writeln!(events, "{}\twrite\t{n}", i + 1).unwrap(),
                    Event::Flush => writeln!(events, "{}\tflush\t0", i + 1).unwrap(),
                }
            }
            fs::write(out.join(format!("events-b{bs}-{operation}.tsv")), events).unwrap();
            assert_eq!(r.memory.used(), 0);
            let mut case = 0usize;
            for (event, kind) in trace.iter().enumerate() {
                let prefixes = match kind {
                    Event::Write(n) => vec![0, n / 2, *n],
                    Event::Flush => vec![0],
                };
                for immediate in [false, true] {
                    for persist in [false, true] {
                        for prefix in &prefixes {
                            case += 1;
                            total += 1;
                            let r = resources();
                            let mut model = Model::new(&original);
                            model.cut = event + 1;
                            model.prefix = *prefix;
                            model.immediate = immediate;
                            model.persist = persist;
                            let mut owner =
                                crate::fs_ext::ExtJournalSession::open(model, public_limits(), &r)
                                    .unwrap();
                            let error = overwrite_native_operation(
                                &mut owner,
                                source_name,
                                write_offset,
                                &input,
                                &r,
                            )
                            .unwrap_err();
                            writeln!(
                                errors,
                                "bs={bs} operation={operation} case={case} error={error:?}"
                            )
                            .unwrap();
                            assert!(error.to_string().contains("owned native cut"));
                            let (model, state) = owner.into_storage();
                            assert!(model.hit);
                            assert_eq!(state, crate::fs_ext::ExtJournalState::NeedsRecovery);
                            let (prehash, prepath) = saved(&out, &model.durable);
                            let mut cold = crate::fs_ext::ExtJournalSession::open_for_recovery(
                                Model::new(&model.durable),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            cold.recover(&r.cancellation).unwrap();
                            let (recovered, state) = cold.into_storage();
                            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
                            assert_eq!(recovered.visible, recovered.durable);
                            let old = home_equal(&recovered.visible, &original, bs, &old_mask);
                            let new = home_equal(&recovered.visible, &expected, bs, &journal);
                            assert_ne!(
                                old,
                                new,
                                "namespace partial outcome {bs} {operation} event={} prefix={prefix}",
                                event + 1
                            );
                            let result = if old { "old" } else { "new" };
                            let check = crate::fs_ext::ExtJournalSession::open(
                                Model::new(&recovered.visible),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            for path in [source_name, alias] {
                                namespace_v4_path_contents(
                                    &check,
                                    &[path],
                                    if new { &final_payload } else { &payload },
                                    &r,
                                );
                            }
                            drop(check);
                            let (retryhash, retrypath) = saved(&out, &recovered.visible);
                            writeln!(manifest,"{bs}\t{operation}\t{case}\t{}\t{}\t{}\t{prefix}\t{prehash}\t{prepath}\t{retryhash}\t{retrypath}\t{result}",event+1,if immediate{"immediate"}else{"volatile"},match kind{Event::Write(_)=>"write",Event::Flush=>if persist{"flush-persist"}else{"flush-none"}}).unwrap();
                            assert_eq!(r.memory.used(), 0);
                        }
                    }
                }
            }
        }
        checked(&corpus.join(f[2]), f[3]);
        checked(&corpus.join(f[8]), f[9]);
        checked(&payload_path, &payload_hash);
    }
    assert_eq!(snapshot(), before);
    fs::write(out.join("source-end.sha256"), snapshot()).unwrap();
    fs::write(out.join("namespace-cuts.tsv"), manifest).unwrap();
    fs::write(out.join("observations.txt"), observations).unwrap();
    fs::write(out.join("cut-errors.txt"), errors).unwrap();
    fs::write(out.join("enospc.tsv"), enospc).unwrap();
    checked(
        &corpus.join("receipt.json"),
        "c28089d995c623a6cb90d2b32d2255cbccda5d1550801cd6c3325404b3516d61",
    );
    checked(
        &corpus.join("cases.tsv"),
        "03f67dbe987473994e8ed2c997f6524162d8d961278e7eea16b8100ed5f735fa",
    );
    fs::write(out.join("report.txt"),format!("complete=true\ncases={total}\nscope=public classic truncate modeled cuts, exact OLD/NEW homes; independent native verification required; offline modeled qualification only; no kernel or hardware crash claim\n")).unwrap();
}

fn sparse_native_operation(
    s: &mut crate::fs_ext::ExtJournalSession<Model>,
    name: &[u8],
    length: u64,
    r: &Resources,
) -> io::Result<()> {
    let file = s.file_at(&names(name), &r.cancellation)?;
    s.extend_sparse(&file, length, planning(), &r.cancellation)
}
#[test]
#[ignore = "requires pinned e2fsprogs corpus, fresh namespace evidence and independent native verification"]
fn native_owned_ext3_ordered_sparse_extend_cuts() {
    let corpus = required("PARTMGR_EXT_SPARSE_CORPUS");
    let root = required("PARTMGR_GATE_SOURCE_ROOT");
    let out = required("PARTMGR_EXT_SPARSE_EVIDENCE");
    fs::create_dir(&out).unwrap();
    fs::create_dir(out.join("images")).unwrap();
    let receipt = checked(
        &corpus.join("receipt.json"),
        "baa7e6523c02552b72b4bc9317473c98cfa9bd2c137f690da8e65b45e4ef156c",
    );
    fs::write(out.join("fixture-receipt.json"), receipt).unwrap();
    let models = checked(
        &corpus.join("cases.tsv"),
        "712ff5d9cc2c66454986e55e4fe4bf882737a20abffc8fa4910221e17745519f",
    );
    let snapshot = || {
        let mut manifest = String::new();
        for (name, bytes) in compiled_sources() {
            assert_eq!(fs::read(root.join(name)).unwrap(), *bytes);
            writeln!(manifest, "{}  {name}", hash(bytes)).unwrap();
        }
        manifest
    };
    let before = snapshot();
    fs::write(out.join("source-start.sha256"), &before).unwrap();
    for (name, bytes) in compiled_sources() {
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fs::write(
        out.join("gate-binary"),
        fs::read(std::env::current_exe().unwrap()).unwrap(),
    )
    .unwrap();
    let mut manifest = String::from(
        "bs\toperation\tcase\tevent\tmodel\tfault_kind\tprefix\tpre_sha256\tpre_path\tretried_sha256\tretried_path\tresult\n",
    );
    let mut enospc = String::from("bs\tsource_sha256\tafter_sha256\twrites\tflushes\terror\n");
    let mut observations = String::new();
    let mut errors = String::new();
    let mut total = 0usize;
    for line in std::str::from_utf8(&models).unwrap().lines() {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 11);
        let bs: usize = f[0].parse().unwrap();
        let variant = f[1];
        let original = checked(&corpus.join(f[2]), f[3]);
        let source_name = f[4].strip_prefix('/').unwrap().as_bytes();
        let inode_number: u32 = f[5].parse().unwrap();
        let old_length: usize = f[6].parse().unwrap();
        let new_length: usize = f[7].parse().unwrap();
        assert!(new_length > old_length);
        let payload = checked(&corpus.join(f[8]), f[9]);
        let mut final_payload = payload.clone();
        final_payload.resize(new_length, 0);
        assert_eq!(payload.len(), old_length);
        let alias = f[10].strip_prefix('/').unwrap().as_bytes();
        let operation = format!("sparse-extend-{variant}");
        if variant == "enospc" {
            let r = resources();
            let mut owner =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            let file = owner.file_at(&names(source_name), &r.cancellation).unwrap();
            let error = owner
                .extend_sparse(&file, new_length as u64, planning(), &r.cancellation)
                .unwrap_err();
            assert!(format!("{error:?}").contains("InvalidOperation"));
            assert!(
                error
                    .to_string()
                    .contains("ext2 no audited free blocks available")
            );
            drop(file);
            let (model, state) = owner.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            assert!(model.trace.is_empty());
            assert_eq!(model.visible, original);
            assert_eq!(model.durable, original);
            writeln!(
                enospc,
                "{bs}\t{}\t{}\t0\t0\tInvalidOperation:no-audited-free-blocks",
                hash(&original),
                hash(&model.visible)
            )
            .unwrap();
            assert_eq!(r.memory.used(), 0);
            checked(&corpus.join(f[2]), f[3]);
            checked(&corpus.join(f[8]), f[9]);
            continue;
        }
        let r = resources();
        let boot =
            bootstrap::Bootstrap::read(&Model::new(&original), 65536, 32_000_000, &r).unwrap();
        let journal = boot.physical_blocks.clone();
        drop(boot);
        assert_eq!(r.memory.used(), 0);
        fs::write(
            out.join(format!("journal-map-b{bs}.tsv")),
            journal.iter().map(|n| format!("{n}\n")).collect::<String>(),
        )
        .unwrap();
        {
            let r = resources();
            let mut baseline =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            for path in [source_name, alias] {
                namespace_v4_path_contents(&baseline, &[path], &payload, &r);
            }
            sparse_native_operation(&mut baseline, source_name, new_length as u64, &r).unwrap();
            for path in [source_name, alias] {
                namespace_v4_path_contents(&baseline, &[path], &final_payload, &r);
            }
            let (baseline, state) = baseline.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            assert_eq!(baseline.visible, baseline.durable);
            let trace = baseline.trace.clone();
            let expected = baseline.visible;
            let mut old_mask = journal.clone();
            {
                let original_source = Model::new(&original);
                let expected_source = Model::new(&expected);
                let (before_decoder, before_proof) =
                    super::super::ExtDecoder::open_native_clean(&original_source, 91, &r).unwrap();
                let (after_decoder, after_proof) =
                    super::super::ExtDecoder::open_native_clean(&expected_source, 92, &r).unwrap();
                let before_map = before_decoder
                    .file_map(inode_number, 65536, &r, false)
                    .unwrap();
                let after_map = after_decoder
                    .file_map(inode_number, 65536, &r, false)
                    .unwrap();
                let physical = |map: &crate::fs_ext::ExtDecodedFileMap, logical: u64| {
                    let extent = map
                        .extents
                        .iter()
                        .find(|extent| {
                            extent.offset <= logical && logical < extent.offset + extent.length
                        })
                        .unwrap();
                    match extent.kind {
                        crate::fs_file::ExtentKind::Data(at) => {
                            Some(((at + logical - extent.offset) / bs as u64) as u32)
                        }
                        crate::fs_file::ExtentKind::Hole => None,
                        _ => panic!("unsupported source extent"),
                    }
                };
                let mut cow = String::from("logical_block\tsource_block\tfresh_block\n");
                // No sentinel physical zero: no original last block exists for empty files.
                let old_tail = if old_length != 0 && !old_length.is_multiple_of(bs) {
                    physical(&before_map, (old_length / bs * bs) as u64)
                } else {
                    None
                };
                if let Some(old_block) = old_tail {
                    let logical_block = old_length / bs;
                    let logical = (logical_block * bs) as u64;
                    let fresh = physical(&after_map, logical).unwrap();
                    assert_ne!(old_block, fresh);
                    let g = before_decoder.geometry();
                    let group = (fresh - g.first) / g.blocks_per_group;
                    let bit = ((fresh - g.first) % g.blocks_per_group) as usize;
                    let bitmap = before_decoder.group(group).unwrap()[0] as usize * bs;
                    assert_eq!(original[bitmap + bit / 8] & (1 << (bit % 8)), 0);
                    assert!(!journal.contains(&fresh));
                    let prefix = old_length % bs;
                    let mut body = vec![0; bs];
                    let old_at = old_block as usize * bs;
                    body[..prefix].copy_from_slice(&original[old_at..old_at + prefix]);
                    let fresh_at = fresh as usize * bs;
                    assert_eq!(body, expected[fresh_at..fresh_at + bs]);
                    old_mask.push(fresh);
                    writeln!(cow, "{logical_block}\t{old_block}\t{fresh}").unwrap();
                }
                for logical_block in 0..new_length.div_ceil(bs) {
                    let logical = (logical_block * bs) as u64;
                    let current = physical(&after_map, logical);
                    if logical_block >= old_length.div_ceil(bs) {
                        assert!(current.is_none());
                    } else if old_tail.is_none() || logical_block != old_length / bs {
                        assert_eq!(current, physical(&before_map, logical));
                    }
                }
                for extent in &before_map.extents {
                    if let crate::fs_file::ExtentKind::Data(at) = extent.kind {
                        for offset in
                            (0..extent.length.div_ceil(bs as u64)).map(|n| at + n * bs as u64)
                        {
                            let at = offset as usize;
                            assert_eq!(&original[at..at + bs], &expected[at..at + bs]);
                        }
                    }
                }
                let old_inode = before_decoder.inode(inode_number, &r).unwrap();
                let new_inode = after_decoder.inode(inode_number, &r).unwrap();
                assert_eq!(new_inode.len(), new_length as u64);
                assert_eq!(
                    &old_inode.raw_metadata()[28..32],
                    &new_inode.raw_metadata()[28..32]
                );
                for range in [0..4, 8..28, 32..40, 88..128] {
                    assert_eq!(
                        &old_inode.raw_metadata()[range.clone()],
                        &new_inode.raw_metadata()[range]
                    );
                }
                fs::write(out.join(format!("cow-b{bs}-{operation}.tsv")), cow).unwrap();
                drop((
                    before_map,
                    after_map,
                    before_decoder,
                    after_decoder,
                    before_proof,
                    after_proof,
                ));
            }
            let (h, path) = saved(&out, &expected);
            writeln!(
                observations,
                "bs={bs} operation={operation} events={} baseline={path}",
                trace.len()
            )
            .unwrap();
            assert_eq!(path, format!("images/{h}.raw"));
            let mut events = String::from("event\tkind\tbytes\n");
            for (i, event) in trace.iter().enumerate() {
                match event {
                    Event::Write(n) => writeln!(events, "{}\twrite\t{n}", i + 1).unwrap(),
                    Event::Flush => writeln!(events, "{}\tflush\t0", i + 1).unwrap(),
                }
            }
            fs::write(out.join(format!("events-b{bs}-{operation}.tsv")), events).unwrap();
            assert_eq!(r.memory.used(), 0);
            let mut case = 0usize;
            for (event, kind) in trace.iter().enumerate() {
                let prefixes = match kind {
                    Event::Write(n) => vec![0, n / 2, *n],
                    Event::Flush => vec![0],
                };
                for immediate in [false, true] {
                    for persist in [false, true] {
                        for prefix in &prefixes {
                            case += 1;
                            total += 1;
                            let r = resources();
                            let mut model = Model::new(&original);
                            model.cut = event + 1;
                            model.prefix = *prefix;
                            model.immediate = immediate;
                            model.persist = persist;
                            let mut owner =
                                crate::fs_ext::ExtJournalSession::open(model, public_limits(), &r)
                                    .unwrap();
                            let error = sparse_native_operation(
                                &mut owner,
                                source_name,
                                new_length as u64,
                                &r,
                            )
                            .unwrap_err();
                            writeln!(
                                errors,
                                "bs={bs} operation={operation} case={case} error={error:?}"
                            )
                            .unwrap();
                            assert!(error.to_string().contains("owned native cut"));
                            let (model, state) = owner.into_storage();
                            assert!(model.hit);
                            assert_eq!(state, crate::fs_ext::ExtJournalState::NeedsRecovery);
                            let (prehash, prepath) = saved(&out, &model.durable);
                            let mut cold = crate::fs_ext::ExtJournalSession::open_for_recovery(
                                Model::new(&model.durable),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            cold.recover(&r.cancellation).unwrap();
                            let (recovered, state) = cold.into_storage();
                            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
                            assert_eq!(recovered.visible, recovered.durable);
                            let old = home_equal(&recovered.visible, &original, bs, &old_mask);
                            let new = home_equal(&recovered.visible, &expected, bs, &journal);
                            assert_ne!(
                                old,
                                new,
                                "namespace partial outcome {bs} {operation} event={} prefix={prefix}",
                                event + 1
                            );
                            let result = if old { "old" } else { "new" };
                            let check = crate::fs_ext::ExtJournalSession::open(
                                Model::new(&recovered.visible),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            for path in [source_name, alias] {
                                namespace_v4_path_contents(
                                    &check,
                                    &[path],
                                    if new { &final_payload } else { &payload },
                                    &r,
                                );
                            }
                            drop(check);
                            let (retryhash, retrypath) = saved(&out, &recovered.visible);
                            writeln!(manifest,"{bs}\t{operation}\t{case}\t{}\t{}\t{}\t{prefix}\t{prehash}\t{prepath}\t{retryhash}\t{retrypath}\t{result}",event+1,if immediate{"immediate"}else{"volatile"},match kind{Event::Write(_)=>"write",Event::Flush=>if persist{"flush-persist"}else{"flush-none"}}).unwrap();
                            assert_eq!(r.memory.used(), 0);
                        }
                    }
                }
            }
        }
        checked(&corpus.join(f[2]), f[3]);
        checked(&corpus.join(f[8]), f[9]);
    }
    assert_eq!(snapshot(), before);
    fs::write(out.join("source-end.sha256"), snapshot()).unwrap();
    fs::write(out.join("namespace-cuts.tsv"), manifest).unwrap();
    fs::write(out.join("observations.txt"), observations).unwrap();
    fs::write(out.join("cut-errors.txt"), errors).unwrap();
    fs::write(out.join("enospc.tsv"), enospc).unwrap();
    checked(
        &corpus.join("receipt.json"),
        "baa7e6523c02552b72b4bc9317473c98cfa9bd2c137f690da8e65b45e4ef156c",
    );
    checked(
        &corpus.join("cases.tsv"),
        "712ff5d9cc2c66454986e55e4fe4bf882737a20abffc8fa4910221e17745519f",
    );
    fs::write(out.join("report.txt"),format!("complete=true\ncases={total}\nscope=public classic sparse extension modeled cuts, exact OLD/NEW homes; independent native verification required; offline modeled qualification only; no kernel or hardware crash claim\n")).unwrap();
}

// Independent bounded original regular allocation traversal: inline symlink bytes
// are never interpreted as block pointers, and allocated EOF suffixes are included.
fn symlink_regular_unchanged(old: &[u8], new: &[u8], bs: usize) {
    fn u32at(raw: &[u8], at: usize) -> usize {
        u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) as usize
    }
    fn tree(old: &[u8], new: &[u8], bs: usize, block: usize, depth: usize, work: &mut usize) {
        if block == 0 {
            return;
        }
        *work = work
            .checked_sub(1)
            .expect("bounded classic allocation traversal");
        let at = block.checked_mul(bs).unwrap();
        assert!(at + bs <= old.len());
        if depth == 0 {
            assert_eq!(
                &old[at..at + bs],
                &new[at..at + bs],
                "original regular physical data block {block}"
            );
        } else {
            for slot in 0..bs / 4 {
                tree(old, new, bs, u32at(old, at + slot * 4), depth - 1, work);
            }
        }
    }
    assert_eq!(old.len(), new.len());
    assert_eq!(old.len(), 16 << 20);
    let count = u32at(old, 1024);
    let ipg = u32at(old, 1064);
    let first = u32at(old, 1044);
    assert_eq!(u16::from_le_bytes(old[1112..1114].try_into().unwrap()), 128);
    let mut work = old.len() / bs * 4;
    for number in 1..=count {
        let group = (number - 1) / ipg;
        let bit = (number - 1) % ipg;
        let desc = (first + 1) * bs + group * 32;
        let bitmap = u32at(old, desc + 4) * bs;
        if old[bitmap + bit / 8] & (1 << (bit % 8)) == 0 {
            continue;
        }
        let inode = u32at(old, desc + 8) * bs + bit * 128;
        let mode = u16::from_le_bytes(old[inode..inode + 2].try_into().unwrap());
        if mode & 0xf000 != 0x8000 || number == 8 {
            continue;
        }
        for slot in 0..12 {
            tree(
                old,
                new,
                bs,
                u32at(old, inode + 40 + slot * 4),
                0,
                &mut work,
            );
        }
        for depth in 1..=3 {
            tree(
                old,
                new,
                bs,
                u32at(old, inode + 40 + (11 + depth) * 4),
                depth,
                &mut work,
            );
        }
    }
}

// Receipt-derived static records: no JSON parser or production oracle reuse.
struct SymlinkCase {
    bs: usize,
    operation: &'static str,
    kind: &'static str,
    image: &'static str,
    image_sha: &'static str,
    source: &'static str,
    alias: &'static str,
    old_target: &'static str,
    old_sha: &'static str,
    target: &'static str,
    target_sha: &'static str,
    destination: &'static str,
    refuse: bool,
}
fn symlink_cases() -> &'static [SymlinkCase] {
    &[
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-create-fast1",
            kind: "create-fast1",
            image: "symlink-b1024-plain-before.raw",
            image_sha: "32ce0892cd876bf9385b0e667c799231ce068b1a06f0f9bdeebcc83f3c0f2dbe",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-plain-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-create-fast59",
            kind: "create-fast59",
            image: "symlink-b1024-plain-before.raw",
            image_sha: "32ce0892cd876bf9385b0e667c799231ce068b1a06f0f9bdeebcc83f3c0f2dbe",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-plain-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-create-slow60",
            kind: "create-slow60",
            image: "symlink-b1024-plain-before.raw",
            image_sha: "32ce0892cd876bf9385b0e667c799231ce068b1a06f0f9bdeebcc83f3c0f2dbe",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-create-slowmax",
            kind: "create-slowmax",
            image: "symlink-b1024-plain-before.raw",
            image_sha: "32ce0892cd876bf9385b0e667c799231ce068b1a06f0f9bdeebcc83f3c0f2dbe",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-plain-slowmax.bin",
            target_sha: "9c0a88fbdd158eae7ec2b2fa1a99fbf755ec6c752a7197ad0ad7650a01d39c2c",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b1024-plain-before.raw",
            image_sha: "32ce0892cd876bf9385b0e667c799231ce068b1a06f0f9bdeebcc83f3c0f2dbe",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b1024-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b1024-plain-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b1024-plain-before.raw",
            image_sha: "32ce0892cd876bf9385b0e667c799231ce068b1a06f0f9bdeebcc83f3c0f2dbe",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b1024-plain-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b1024-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b1024-plain-before.raw",
            image_sha: "32ce0892cd876bf9385b0e667c799231ce068b1a06f0f9bdeebcc83f3c0f2dbe",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b1024-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b1024-plain-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b1024-plain-before.raw",
            image_sha: "32ce0892cd876bf9385b0e667c799231ce068b1a06f0f9bdeebcc83f3c0f2dbe",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b1024-plain-slowmax.bin",
            old_sha: "9c0a88fbdd158eae7ec2b2fa1a99fbf755ec6c752a7197ad0ad7650a01d39c2c",
            target: "target-b1024-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-rename-fast",
            kind: "rename-fast",
            image: "symlink-b1024-plain-before.raw",
            image_sha: "32ce0892cd876bf9385b0e667c799231ce068b1a06f0f9bdeebcc83f3c0f2dbe",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b1024-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-rename-slow",
            kind: "rename-slow",
            image: "symlink-b1024-plain-before.raw",
            image_sha: "32ce0892cd876bf9385b0e667c799231ce068b1a06f0f9bdeebcc83f3c0f2dbe",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b1024-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-unlink-alias-fast",
            kind: "unlink-alias-fast",
            image: "symlink-b1024-plain-before.raw",
            image_sha: "32ce0892cd876bf9385b0e667c799231ce068b1a06f0f9bdeebcc83f3c0f2dbe",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b1024-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-unlink-alias-slow",
            kind: "unlink-alias-slow",
            image: "symlink-b1024-plain-before.raw",
            image_sha: "32ce0892cd876bf9385b0e667c799231ce068b1a06f0f9bdeebcc83f3c0f2dbe",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b1024-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-unlink-final-fast59",
            kind: "unlink-final-fast59",
            image: "symlink-b1024-plain-final-fast59.raw",
            image_sha: "ec8e641ff120b838cc60f0fc4b27fd08ec7f21b650a2b99fc3848a48355fc1c5",
            source: "/symlink-fast59",
            alias: "",
            old_target: "target-b1024-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-unlink-final-slow60",
            kind: "unlink-final-slow60",
            image: "symlink-b1024-plain-final-slow60.raw",
            image_sha: "742d5e3d6db763eb7e5ed374ce65c784ce17bfb02753a4bdd6c83dcdeb55f28a",
            source: "/symlink-slow60",
            alias: "",
            old_target: "target-b1024-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-no-free-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b1024-plain-no-free.raw",
            image_sha: "20b178ac8c163d1ba445738cc511a8c4823d96434f6a2e1e72be3632229e7cb6",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b1024-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b1024-plain-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-no-free-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b1024-plain-no-free.raw",
            image_sha: "20b178ac8c163d1ba445738cc511a8c4823d96434f6a2e1e72be3632229e7cb6",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b1024-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b1024-plain-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-no-free-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b1024-plain-no-free.raw",
            image_sha: "20b178ac8c163d1ba445738cc511a8c4823d96434f6a2e1e72be3632229e7cb6",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b1024-plain-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b1024-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: true,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-no-free-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b1024-plain-no-free.raw",
            image_sha: "20b178ac8c163d1ba445738cc511a8c4823d96434f6a2e1e72be3632229e7cb6",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b1024-plain-slowmax.bin",
            old_sha: "9c0a88fbdd158eae7ec2b2fa1a99fbf755ec6c752a7197ad0ad7650a01d39c2c",
            target: "target-b1024-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: true,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-no-free-create-fast1",
            kind: "create-fast1",
            image: "symlink-b1024-plain-no-free.raw",
            image_sha: "20b178ac8c163d1ba445738cc511a8c4823d96434f6a2e1e72be3632229e7cb6",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-plain-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-plain-no-free-create-slow60",
            kind: "create-slow60",
            image: "symlink-b1024-plain-no-free.raw",
            image_sha: "20b178ac8c163d1ba445738cc511a8c4823d96434f6a2e1e72be3632229e7cb6",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: true,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-create-fast1",
            kind: "create-fast1",
            image: "symlink-b2048-plain-before.raw",
            image_sha: "64188a07458c90c4534b3900552d6ca552cb136d335e9590781c5197d1f600a7",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-plain-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-create-fast59",
            kind: "create-fast59",
            image: "symlink-b2048-plain-before.raw",
            image_sha: "64188a07458c90c4534b3900552d6ca552cb136d335e9590781c5197d1f600a7",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-plain-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-create-slow60",
            kind: "create-slow60",
            image: "symlink-b2048-plain-before.raw",
            image_sha: "64188a07458c90c4534b3900552d6ca552cb136d335e9590781c5197d1f600a7",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-create-slowmax",
            kind: "create-slowmax",
            image: "symlink-b2048-plain-before.raw",
            image_sha: "64188a07458c90c4534b3900552d6ca552cb136d335e9590781c5197d1f600a7",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-plain-slowmax.bin",
            target_sha: "dd84b9f746e3f39435fff5483fd87b050c457c0b4379a54fefdbd7f9bd673fbd",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b2048-plain-before.raw",
            image_sha: "64188a07458c90c4534b3900552d6ca552cb136d335e9590781c5197d1f600a7",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b2048-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b2048-plain-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b2048-plain-before.raw",
            image_sha: "64188a07458c90c4534b3900552d6ca552cb136d335e9590781c5197d1f600a7",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b2048-plain-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b2048-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b2048-plain-before.raw",
            image_sha: "64188a07458c90c4534b3900552d6ca552cb136d335e9590781c5197d1f600a7",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b2048-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b2048-plain-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b2048-plain-before.raw",
            image_sha: "64188a07458c90c4534b3900552d6ca552cb136d335e9590781c5197d1f600a7",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b2048-plain-slowmax.bin",
            old_sha: "dd84b9f746e3f39435fff5483fd87b050c457c0b4379a54fefdbd7f9bd673fbd",
            target: "target-b2048-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-rename-fast",
            kind: "rename-fast",
            image: "symlink-b2048-plain-before.raw",
            image_sha: "64188a07458c90c4534b3900552d6ca552cb136d335e9590781c5197d1f600a7",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b2048-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-rename-slow",
            kind: "rename-slow",
            image: "symlink-b2048-plain-before.raw",
            image_sha: "64188a07458c90c4534b3900552d6ca552cb136d335e9590781c5197d1f600a7",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b2048-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-unlink-alias-fast",
            kind: "unlink-alias-fast",
            image: "symlink-b2048-plain-before.raw",
            image_sha: "64188a07458c90c4534b3900552d6ca552cb136d335e9590781c5197d1f600a7",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b2048-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-unlink-alias-slow",
            kind: "unlink-alias-slow",
            image: "symlink-b2048-plain-before.raw",
            image_sha: "64188a07458c90c4534b3900552d6ca552cb136d335e9590781c5197d1f600a7",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b2048-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-unlink-final-fast59",
            kind: "unlink-final-fast59",
            image: "symlink-b2048-plain-final-fast59.raw",
            image_sha: "036657d2a4395df9582ebbf415b53f5219549f2af7f3f0e0debedf7e8a83dace",
            source: "/symlink-fast59",
            alias: "",
            old_target: "target-b2048-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-unlink-final-slow60",
            kind: "unlink-final-slow60",
            image: "symlink-b2048-plain-final-slow60.raw",
            image_sha: "81285d09547ed4e66040b7f2c9a290a2db1cb3ce9c47a0c26de93d8e3612606f",
            source: "/symlink-slow60",
            alias: "",
            old_target: "target-b2048-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-no-free-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b2048-plain-no-free.raw",
            image_sha: "8084752ca3c7ea28f9e0ca4d79a921032c8f7a5c52adc1ce1bf502249b51e3de",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b2048-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b2048-plain-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-no-free-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b2048-plain-no-free.raw",
            image_sha: "8084752ca3c7ea28f9e0ca4d79a921032c8f7a5c52adc1ce1bf502249b51e3de",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b2048-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b2048-plain-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-no-free-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b2048-plain-no-free.raw",
            image_sha: "8084752ca3c7ea28f9e0ca4d79a921032c8f7a5c52adc1ce1bf502249b51e3de",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b2048-plain-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b2048-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: true,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-no-free-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b2048-plain-no-free.raw",
            image_sha: "8084752ca3c7ea28f9e0ca4d79a921032c8f7a5c52adc1ce1bf502249b51e3de",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b2048-plain-slowmax.bin",
            old_sha: "dd84b9f746e3f39435fff5483fd87b050c457c0b4379a54fefdbd7f9bd673fbd",
            target: "target-b2048-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: true,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-no-free-create-fast1",
            kind: "create-fast1",
            image: "symlink-b2048-plain-no-free.raw",
            image_sha: "8084752ca3c7ea28f9e0ca4d79a921032c8f7a5c52adc1ce1bf502249b51e3de",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-plain-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-plain-no-free-create-slow60",
            kind: "create-slow60",
            image: "symlink-b2048-plain-no-free.raw",
            image_sha: "8084752ca3c7ea28f9e0ca4d79a921032c8f7a5c52adc1ce1bf502249b51e3de",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: true,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-create-fast1",
            kind: "create-fast1",
            image: "symlink-b4096-plain-before.raw",
            image_sha: "4688ada4a64d6bdb9a29232be8d69b3ba869d2a62e30b6a3589b8152d565f2c7",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-plain-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-create-fast59",
            kind: "create-fast59",
            image: "symlink-b4096-plain-before.raw",
            image_sha: "4688ada4a64d6bdb9a29232be8d69b3ba869d2a62e30b6a3589b8152d565f2c7",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-plain-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-create-slow60",
            kind: "create-slow60",
            image: "symlink-b4096-plain-before.raw",
            image_sha: "4688ada4a64d6bdb9a29232be8d69b3ba869d2a62e30b6a3589b8152d565f2c7",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-create-slowmax",
            kind: "create-slowmax",
            image: "symlink-b4096-plain-before.raw",
            image_sha: "4688ada4a64d6bdb9a29232be8d69b3ba869d2a62e30b6a3589b8152d565f2c7",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-plain-slowmax.bin",
            target_sha: "c3b9d3612f914704e2481c14ea12d442716643951b0da09957da441429f58ea1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b4096-plain-before.raw",
            image_sha: "4688ada4a64d6bdb9a29232be8d69b3ba869d2a62e30b6a3589b8152d565f2c7",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b4096-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b4096-plain-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b4096-plain-before.raw",
            image_sha: "4688ada4a64d6bdb9a29232be8d69b3ba869d2a62e30b6a3589b8152d565f2c7",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b4096-plain-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b4096-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b4096-plain-before.raw",
            image_sha: "4688ada4a64d6bdb9a29232be8d69b3ba869d2a62e30b6a3589b8152d565f2c7",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b4096-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b4096-plain-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b4096-plain-before.raw",
            image_sha: "4688ada4a64d6bdb9a29232be8d69b3ba869d2a62e30b6a3589b8152d565f2c7",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b4096-plain-slowmax.bin",
            old_sha: "c3b9d3612f914704e2481c14ea12d442716643951b0da09957da441429f58ea1",
            target: "target-b4096-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-rename-fast",
            kind: "rename-fast",
            image: "symlink-b4096-plain-before.raw",
            image_sha: "4688ada4a64d6bdb9a29232be8d69b3ba869d2a62e30b6a3589b8152d565f2c7",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b4096-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-rename-slow",
            kind: "rename-slow",
            image: "symlink-b4096-plain-before.raw",
            image_sha: "4688ada4a64d6bdb9a29232be8d69b3ba869d2a62e30b6a3589b8152d565f2c7",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b4096-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-unlink-alias-fast",
            kind: "unlink-alias-fast",
            image: "symlink-b4096-plain-before.raw",
            image_sha: "4688ada4a64d6bdb9a29232be8d69b3ba869d2a62e30b6a3589b8152d565f2c7",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b4096-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-unlink-alias-slow",
            kind: "unlink-alias-slow",
            image: "symlink-b4096-plain-before.raw",
            image_sha: "4688ada4a64d6bdb9a29232be8d69b3ba869d2a62e30b6a3589b8152d565f2c7",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b4096-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-unlink-final-fast59",
            kind: "unlink-final-fast59",
            image: "symlink-b4096-plain-final-fast59.raw",
            image_sha: "28f0954c42872a37a23751b8d1b72f838d0c889e256cc6957d3e5c0cae447567",
            source: "/symlink-fast59",
            alias: "",
            old_target: "target-b4096-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-unlink-final-slow60",
            kind: "unlink-final-slow60",
            image: "symlink-b4096-plain-final-slow60.raw",
            image_sha: "68cddb8e3014b9844696852a4bc42f56daee27b9bd1a666815cc6e3ba161e820",
            source: "/symlink-slow60",
            alias: "",
            old_target: "target-b4096-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-no-free-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b4096-plain-no-free.raw",
            image_sha: "2ce269aa313e5bc69b0bb00d2d5fb3ce1cada472a7171fbe149d9a99e1fe18a4",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b4096-plain-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b4096-plain-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-no-free-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b4096-plain-no-free.raw",
            image_sha: "2ce269aa313e5bc69b0bb00d2d5fb3ce1cada472a7171fbe149d9a99e1fe18a4",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b4096-plain-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b4096-plain-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-no-free-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b4096-plain-no-free.raw",
            image_sha: "2ce269aa313e5bc69b0bb00d2d5fb3ce1cada472a7171fbe149d9a99e1fe18a4",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b4096-plain-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b4096-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: true,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-no-free-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b4096-plain-no-free.raw",
            image_sha: "2ce269aa313e5bc69b0bb00d2d5fb3ce1cada472a7171fbe149d9a99e1fe18a4",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b4096-plain-slowmax.bin",
            old_sha: "c3b9d3612f914704e2481c14ea12d442716643951b0da09957da441429f58ea1",
            target: "target-b4096-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: true,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-no-free-create-fast1",
            kind: "create-fast1",
            image: "symlink-b4096-plain-no-free.raw",
            image_sha: "2ce269aa313e5bc69b0bb00d2d5fb3ce1cada472a7171fbe149d9a99e1fe18a4",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-plain-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/new-symlink",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-plain-no-free-create-slow60",
            kind: "create-slow60",
            image: "symlink-b4096-plain-no-free.raw",
            image_sha: "2ce269aa313e5bc69b0bb00d2d5fb3ce1cada472a7171fbe149d9a99e1fe18a4",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-plain-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/new-symlink",
            refuse: true,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-create-fast1",
            kind: "create-fast1",
            image: "symlink-b1024-grow-direct-before.raw",
            image_sha: "7236ea074e615b217f11cd2e8850dee9410bd7fa9dbba05e78bdf89adfd6899e",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-grow-direct-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-create-fast59",
            kind: "create-fast59",
            image: "symlink-b1024-grow-direct-before.raw",
            image_sha: "7236ea074e615b217f11cd2e8850dee9410bd7fa9dbba05e78bdf89adfd6899e",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-grow-direct-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-create-slow60",
            kind: "create-slow60",
            image: "symlink-b1024-grow-direct-before.raw",
            image_sha: "7236ea074e615b217f11cd2e8850dee9410bd7fa9dbba05e78bdf89adfd6899e",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-create-slowmax",
            kind: "create-slowmax",
            image: "symlink-b1024-grow-direct-before.raw",
            image_sha: "7236ea074e615b217f11cd2e8850dee9410bd7fa9dbba05e78bdf89adfd6899e",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-grow-direct-slowmax.bin",
            target_sha: "9c0a88fbdd158eae7ec2b2fa1a99fbf755ec6c752a7197ad0ad7650a01d39c2c",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b1024-grow-direct-before.raw",
            image_sha: "7236ea074e615b217f11cd2e8850dee9410bd7fa9dbba05e78bdf89adfd6899e",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b1024-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b1024-grow-direct-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b1024-grow-direct-before.raw",
            image_sha: "7236ea074e615b217f11cd2e8850dee9410bd7fa9dbba05e78bdf89adfd6899e",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b1024-grow-direct-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b1024-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b1024-grow-direct-before.raw",
            image_sha: "7236ea074e615b217f11cd2e8850dee9410bd7fa9dbba05e78bdf89adfd6899e",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b1024-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b1024-grow-direct-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b1024-grow-direct-before.raw",
            image_sha: "7236ea074e615b217f11cd2e8850dee9410bd7fa9dbba05e78bdf89adfd6899e",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b1024-grow-direct-slowmax.bin",
            old_sha: "9c0a88fbdd158eae7ec2b2fa1a99fbf755ec6c752a7197ad0ad7650a01d39c2c",
            target: "target-b1024-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-rename-fast",
            kind: "rename-fast",
            image: "symlink-b1024-grow-direct-before.raw",
            image_sha: "7236ea074e615b217f11cd2e8850dee9410bd7fa9dbba05e78bdf89adfd6899e",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b1024-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-rename-slow",
            kind: "rename-slow",
            image: "symlink-b1024-grow-direct-before.raw",
            image_sha: "7236ea074e615b217f11cd2e8850dee9410bd7fa9dbba05e78bdf89adfd6899e",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b1024-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-unlink-alias-fast",
            kind: "unlink-alias-fast",
            image: "symlink-b1024-grow-direct-before.raw",
            image_sha: "7236ea074e615b217f11cd2e8850dee9410bd7fa9dbba05e78bdf89adfd6899e",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b1024-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-unlink-alias-slow",
            kind: "unlink-alias-slow",
            image: "symlink-b1024-grow-direct-before.raw",
            image_sha: "7236ea074e615b217f11cd2e8850dee9410bd7fa9dbba05e78bdf89adfd6899e",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b1024-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-unlink-final-fast59",
            kind: "unlink-final-fast59",
            image: "symlink-b1024-grow-direct-final-fast59.raw",
            image_sha: "c18a6baad4928cb025ad337f53890d6802e33517a2210ea7a8643f8084684ff4",
            source: "/symlink-fast59",
            alias: "",
            old_target: "target-b1024-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-unlink-final-slow60",
            kind: "unlink-final-slow60",
            image: "symlink-b1024-grow-direct-final-slow60.raw",
            image_sha: "e5e5638d3b0e1bc149e773199f627e1e3282acf40d949ca5186425426de70e22",
            source: "/symlink-slow60",
            alias: "",
            old_target: "target-b1024-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-no-free-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b1024-grow-direct-no-free.raw",
            image_sha: "13e2ebcf43ee9068efb2c1cd7c7f26d6c531f02968ea1ee9846a31955482c590",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b1024-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b1024-grow-direct-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-no-free-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b1024-grow-direct-no-free.raw",
            image_sha: "13e2ebcf43ee9068efb2c1cd7c7f26d6c531f02968ea1ee9846a31955482c590",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b1024-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b1024-grow-direct-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-no-free-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b1024-grow-direct-no-free.raw",
            image_sha: "13e2ebcf43ee9068efb2c1cd7c7f26d6c531f02968ea1ee9846a31955482c590",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b1024-grow-direct-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b1024-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-no-free-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b1024-grow-direct-no-free.raw",
            image_sha: "13e2ebcf43ee9068efb2c1cd7c7f26d6c531f02968ea1ee9846a31955482c590",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b1024-grow-direct-slowmax.bin",
            old_sha: "9c0a88fbdd158eae7ec2b2fa1a99fbf755ec6c752a7197ad0ad7650a01d39c2c",
            target: "target-b1024-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-no-free-create-fast1",
            kind: "create-fast1",
            image: "symlink-b1024-grow-direct-no-free.raw",
            image_sha: "13e2ebcf43ee9068efb2c1cd7c7f26d6c531f02968ea1ee9846a31955482c590",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-grow-direct-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-direct-no-free-create-slow60",
            kind: "create-slow60",
            image: "symlink-b1024-grow-direct-no-free.raw",
            image_sha: "13e2ebcf43ee9068efb2c1cd7c7f26d6c531f02968ea1ee9846a31955482c590",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-create-fast1",
            kind: "create-fast1",
            image: "symlink-b1024-grow-indirect-before.raw",
            image_sha: "02458c829dd01c368f34369b390e77cda1e86f4876ee7a1ac9498a91042ccdc5",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-grow-indirect-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-create-fast59",
            kind: "create-fast59",
            image: "symlink-b1024-grow-indirect-before.raw",
            image_sha: "02458c829dd01c368f34369b390e77cda1e86f4876ee7a1ac9498a91042ccdc5",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-grow-indirect-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-create-slow60",
            kind: "create-slow60",
            image: "symlink-b1024-grow-indirect-before.raw",
            image_sha: "02458c829dd01c368f34369b390e77cda1e86f4876ee7a1ac9498a91042ccdc5",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-create-slowmax",
            kind: "create-slowmax",
            image: "symlink-b1024-grow-indirect-before.raw",
            image_sha: "02458c829dd01c368f34369b390e77cda1e86f4876ee7a1ac9498a91042ccdc5",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-grow-indirect-slowmax.bin",
            target_sha: "9c0a88fbdd158eae7ec2b2fa1a99fbf755ec6c752a7197ad0ad7650a01d39c2c",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b1024-grow-indirect-before.raw",
            image_sha: "02458c829dd01c368f34369b390e77cda1e86f4876ee7a1ac9498a91042ccdc5",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b1024-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b1024-grow-indirect-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b1024-grow-indirect-before.raw",
            image_sha: "02458c829dd01c368f34369b390e77cda1e86f4876ee7a1ac9498a91042ccdc5",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b1024-grow-indirect-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b1024-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b1024-grow-indirect-before.raw",
            image_sha: "02458c829dd01c368f34369b390e77cda1e86f4876ee7a1ac9498a91042ccdc5",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b1024-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b1024-grow-indirect-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b1024-grow-indirect-before.raw",
            image_sha: "02458c829dd01c368f34369b390e77cda1e86f4876ee7a1ac9498a91042ccdc5",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b1024-grow-indirect-slowmax.bin",
            old_sha: "9c0a88fbdd158eae7ec2b2fa1a99fbf755ec6c752a7197ad0ad7650a01d39c2c",
            target: "target-b1024-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-rename-fast",
            kind: "rename-fast",
            image: "symlink-b1024-grow-indirect-before.raw",
            image_sha: "02458c829dd01c368f34369b390e77cda1e86f4876ee7a1ac9498a91042ccdc5",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b1024-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-rename-slow",
            kind: "rename-slow",
            image: "symlink-b1024-grow-indirect-before.raw",
            image_sha: "02458c829dd01c368f34369b390e77cda1e86f4876ee7a1ac9498a91042ccdc5",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b1024-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-unlink-alias-fast",
            kind: "unlink-alias-fast",
            image: "symlink-b1024-grow-indirect-before.raw",
            image_sha: "02458c829dd01c368f34369b390e77cda1e86f4876ee7a1ac9498a91042ccdc5",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b1024-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-unlink-alias-slow",
            kind: "unlink-alias-slow",
            image: "symlink-b1024-grow-indirect-before.raw",
            image_sha: "02458c829dd01c368f34369b390e77cda1e86f4876ee7a1ac9498a91042ccdc5",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b1024-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-unlink-final-fast59",
            kind: "unlink-final-fast59",
            image: "symlink-b1024-grow-indirect-final-fast59.raw",
            image_sha: "b8ad5266c5834caff7597e483b03af045b7a22f3c618574d00ddcb98b9f62e35",
            source: "/symlink-fast59",
            alias: "",
            old_target: "target-b1024-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-unlink-final-slow60",
            kind: "unlink-final-slow60",
            image: "symlink-b1024-grow-indirect-final-slow60.raw",
            image_sha: "0ac0aac838f5f3c30f4e45c697be6df95ef0400837277a7fec5f73102e604dd1",
            source: "/symlink-slow60",
            alias: "",
            old_target: "target-b1024-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-no-free-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b1024-grow-indirect-no-free.raw",
            image_sha: "9ed47865203d6f18316929663c051067d3bffe1bb4557f50797a9cbe3ee41e00",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b1024-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b1024-grow-indirect-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-no-free-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b1024-grow-indirect-no-free.raw",
            image_sha: "9ed47865203d6f18316929663c051067d3bffe1bb4557f50797a9cbe3ee41e00",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b1024-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b1024-grow-indirect-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-no-free-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b1024-grow-indirect-no-free.raw",
            image_sha: "9ed47865203d6f18316929663c051067d3bffe1bb4557f50797a9cbe3ee41e00",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b1024-grow-indirect-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b1024-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-no-free-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b1024-grow-indirect-no-free.raw",
            image_sha: "9ed47865203d6f18316929663c051067d3bffe1bb4557f50797a9cbe3ee41e00",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b1024-grow-indirect-slowmax.bin",
            old_sha: "9c0a88fbdd158eae7ec2b2fa1a99fbf755ec6c752a7197ad0ad7650a01d39c2c",
            target: "target-b1024-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-no-free-create-fast1",
            kind: "create-fast1",
            image: "symlink-b1024-grow-indirect-no-free.raw",
            image_sha: "9ed47865203d6f18316929663c051067d3bffe1bb4557f50797a9cbe3ee41e00",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-grow-indirect-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 1024,
            operation: "symlink-grow-indirect-no-free-create-slow60",
            kind: "create-slow60",
            image: "symlink-b1024-grow-indirect-no-free.raw",
            image_sha: "9ed47865203d6f18316929663c051067d3bffe1bb4557f50797a9cbe3ee41e00",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b1024-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-create-fast1",
            kind: "create-fast1",
            image: "symlink-b2048-grow-direct-before.raw",
            image_sha: "f490083ec9467b45845f816b970ec32e5bde596d501f2e6136a8b03d47d603b7",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-grow-direct-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-create-fast59",
            kind: "create-fast59",
            image: "symlink-b2048-grow-direct-before.raw",
            image_sha: "f490083ec9467b45845f816b970ec32e5bde596d501f2e6136a8b03d47d603b7",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-grow-direct-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-create-slow60",
            kind: "create-slow60",
            image: "symlink-b2048-grow-direct-before.raw",
            image_sha: "f490083ec9467b45845f816b970ec32e5bde596d501f2e6136a8b03d47d603b7",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-create-slowmax",
            kind: "create-slowmax",
            image: "symlink-b2048-grow-direct-before.raw",
            image_sha: "f490083ec9467b45845f816b970ec32e5bde596d501f2e6136a8b03d47d603b7",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-grow-direct-slowmax.bin",
            target_sha: "dd84b9f746e3f39435fff5483fd87b050c457c0b4379a54fefdbd7f9bd673fbd",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b2048-grow-direct-before.raw",
            image_sha: "f490083ec9467b45845f816b970ec32e5bde596d501f2e6136a8b03d47d603b7",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b2048-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b2048-grow-direct-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b2048-grow-direct-before.raw",
            image_sha: "f490083ec9467b45845f816b970ec32e5bde596d501f2e6136a8b03d47d603b7",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b2048-grow-direct-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b2048-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b2048-grow-direct-before.raw",
            image_sha: "f490083ec9467b45845f816b970ec32e5bde596d501f2e6136a8b03d47d603b7",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b2048-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b2048-grow-direct-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b2048-grow-direct-before.raw",
            image_sha: "f490083ec9467b45845f816b970ec32e5bde596d501f2e6136a8b03d47d603b7",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b2048-grow-direct-slowmax.bin",
            old_sha: "dd84b9f746e3f39435fff5483fd87b050c457c0b4379a54fefdbd7f9bd673fbd",
            target: "target-b2048-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-rename-fast",
            kind: "rename-fast",
            image: "symlink-b2048-grow-direct-before.raw",
            image_sha: "f490083ec9467b45845f816b970ec32e5bde596d501f2e6136a8b03d47d603b7",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b2048-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-rename-slow",
            kind: "rename-slow",
            image: "symlink-b2048-grow-direct-before.raw",
            image_sha: "f490083ec9467b45845f816b970ec32e5bde596d501f2e6136a8b03d47d603b7",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b2048-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-unlink-alias-fast",
            kind: "unlink-alias-fast",
            image: "symlink-b2048-grow-direct-before.raw",
            image_sha: "f490083ec9467b45845f816b970ec32e5bde596d501f2e6136a8b03d47d603b7",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b2048-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-unlink-alias-slow",
            kind: "unlink-alias-slow",
            image: "symlink-b2048-grow-direct-before.raw",
            image_sha: "f490083ec9467b45845f816b970ec32e5bde596d501f2e6136a8b03d47d603b7",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b2048-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-unlink-final-fast59",
            kind: "unlink-final-fast59",
            image: "symlink-b2048-grow-direct-final-fast59.raw",
            image_sha: "738dde17c62bdd6d7c105b214ff995ff86bce482aa29c3a69e345fc976ad5a20",
            source: "/symlink-fast59",
            alias: "",
            old_target: "target-b2048-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-unlink-final-slow60",
            kind: "unlink-final-slow60",
            image: "symlink-b2048-grow-direct-final-slow60.raw",
            image_sha: "ca96a77c3a8969466be0db745e95113069cb8e827be47f2be1e9b0302edb2b8f",
            source: "/symlink-slow60",
            alias: "",
            old_target: "target-b2048-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-no-free-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b2048-grow-direct-no-free.raw",
            image_sha: "037a5447755f778f368386f0d8b3cca48be3ab13449782a00ed3432f236dfd1a",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b2048-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b2048-grow-direct-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-no-free-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b2048-grow-direct-no-free.raw",
            image_sha: "037a5447755f778f368386f0d8b3cca48be3ab13449782a00ed3432f236dfd1a",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b2048-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b2048-grow-direct-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-no-free-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b2048-grow-direct-no-free.raw",
            image_sha: "037a5447755f778f368386f0d8b3cca48be3ab13449782a00ed3432f236dfd1a",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b2048-grow-direct-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b2048-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-no-free-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b2048-grow-direct-no-free.raw",
            image_sha: "037a5447755f778f368386f0d8b3cca48be3ab13449782a00ed3432f236dfd1a",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b2048-grow-direct-slowmax.bin",
            old_sha: "dd84b9f746e3f39435fff5483fd87b050c457c0b4379a54fefdbd7f9bd673fbd",
            target: "target-b2048-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-no-free-create-fast1",
            kind: "create-fast1",
            image: "symlink-b2048-grow-direct-no-free.raw",
            image_sha: "037a5447755f778f368386f0d8b3cca48be3ab13449782a00ed3432f236dfd1a",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-grow-direct-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-direct-no-free-create-slow60",
            kind: "create-slow60",
            image: "symlink-b2048-grow-direct-no-free.raw",
            image_sha: "037a5447755f778f368386f0d8b3cca48be3ab13449782a00ed3432f236dfd1a",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-create-fast1",
            kind: "create-fast1",
            image: "symlink-b2048-grow-indirect-before.raw",
            image_sha: "75e4fa87c9733016144d7a499f8a6b7d47aafb9cf59b1efb1b7f69ec74a051d8",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-grow-indirect-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-create-fast59",
            kind: "create-fast59",
            image: "symlink-b2048-grow-indirect-before.raw",
            image_sha: "75e4fa87c9733016144d7a499f8a6b7d47aafb9cf59b1efb1b7f69ec74a051d8",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-grow-indirect-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-create-slow60",
            kind: "create-slow60",
            image: "symlink-b2048-grow-indirect-before.raw",
            image_sha: "75e4fa87c9733016144d7a499f8a6b7d47aafb9cf59b1efb1b7f69ec74a051d8",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-create-slowmax",
            kind: "create-slowmax",
            image: "symlink-b2048-grow-indirect-before.raw",
            image_sha: "75e4fa87c9733016144d7a499f8a6b7d47aafb9cf59b1efb1b7f69ec74a051d8",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-grow-indirect-slowmax.bin",
            target_sha: "dd84b9f746e3f39435fff5483fd87b050c457c0b4379a54fefdbd7f9bd673fbd",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b2048-grow-indirect-before.raw",
            image_sha: "75e4fa87c9733016144d7a499f8a6b7d47aafb9cf59b1efb1b7f69ec74a051d8",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b2048-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b2048-grow-indirect-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b2048-grow-indirect-before.raw",
            image_sha: "75e4fa87c9733016144d7a499f8a6b7d47aafb9cf59b1efb1b7f69ec74a051d8",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b2048-grow-indirect-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b2048-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b2048-grow-indirect-before.raw",
            image_sha: "75e4fa87c9733016144d7a499f8a6b7d47aafb9cf59b1efb1b7f69ec74a051d8",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b2048-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b2048-grow-indirect-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b2048-grow-indirect-before.raw",
            image_sha: "75e4fa87c9733016144d7a499f8a6b7d47aafb9cf59b1efb1b7f69ec74a051d8",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b2048-grow-indirect-slowmax.bin",
            old_sha: "dd84b9f746e3f39435fff5483fd87b050c457c0b4379a54fefdbd7f9bd673fbd",
            target: "target-b2048-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-rename-fast",
            kind: "rename-fast",
            image: "symlink-b2048-grow-indirect-before.raw",
            image_sha: "75e4fa87c9733016144d7a499f8a6b7d47aafb9cf59b1efb1b7f69ec74a051d8",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b2048-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-rename-slow",
            kind: "rename-slow",
            image: "symlink-b2048-grow-indirect-before.raw",
            image_sha: "75e4fa87c9733016144d7a499f8a6b7d47aafb9cf59b1efb1b7f69ec74a051d8",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b2048-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-unlink-alias-fast",
            kind: "unlink-alias-fast",
            image: "symlink-b2048-grow-indirect-before.raw",
            image_sha: "75e4fa87c9733016144d7a499f8a6b7d47aafb9cf59b1efb1b7f69ec74a051d8",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b2048-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-unlink-alias-slow",
            kind: "unlink-alias-slow",
            image: "symlink-b2048-grow-indirect-before.raw",
            image_sha: "75e4fa87c9733016144d7a499f8a6b7d47aafb9cf59b1efb1b7f69ec74a051d8",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b2048-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-unlink-final-fast59",
            kind: "unlink-final-fast59",
            image: "symlink-b2048-grow-indirect-final-fast59.raw",
            image_sha: "a4858312291ac8efdca6b5b4ebefc2f5f40dea49e6a2e7d277c4858c2ee08180",
            source: "/symlink-fast59",
            alias: "",
            old_target: "target-b2048-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-unlink-final-slow60",
            kind: "unlink-final-slow60",
            image: "symlink-b2048-grow-indirect-final-slow60.raw",
            image_sha: "cec0a50315d8c467c10acf5fb2b79dc678de4836ae1a2a1a4b95271ddba3fd69",
            source: "/symlink-slow60",
            alias: "",
            old_target: "target-b2048-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-no-free-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b2048-grow-indirect-no-free.raw",
            image_sha: "4f9518194f0b8b62437e982a8c2b09452efe075ea68cbf18b2f032a46ef3308c",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b2048-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b2048-grow-indirect-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-no-free-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b2048-grow-indirect-no-free.raw",
            image_sha: "4f9518194f0b8b62437e982a8c2b09452efe075ea68cbf18b2f032a46ef3308c",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b2048-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b2048-grow-indirect-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-no-free-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b2048-grow-indirect-no-free.raw",
            image_sha: "4f9518194f0b8b62437e982a8c2b09452efe075ea68cbf18b2f032a46ef3308c",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b2048-grow-indirect-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b2048-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-no-free-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b2048-grow-indirect-no-free.raw",
            image_sha: "4f9518194f0b8b62437e982a8c2b09452efe075ea68cbf18b2f032a46ef3308c",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b2048-grow-indirect-slowmax.bin",
            old_sha: "dd84b9f746e3f39435fff5483fd87b050c457c0b4379a54fefdbd7f9bd673fbd",
            target: "target-b2048-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-no-free-create-fast1",
            kind: "create-fast1",
            image: "symlink-b2048-grow-indirect-no-free.raw",
            image_sha: "4f9518194f0b8b62437e982a8c2b09452efe075ea68cbf18b2f032a46ef3308c",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-grow-indirect-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 2048,
            operation: "symlink-grow-indirect-no-free-create-slow60",
            kind: "create-slow60",
            image: "symlink-b2048-grow-indirect-no-free.raw",
            image_sha: "4f9518194f0b8b62437e982a8c2b09452efe075ea68cbf18b2f032a46ef3308c",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b2048-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-create-fast1",
            kind: "create-fast1",
            image: "symlink-b4096-grow-direct-before.raw",
            image_sha: "af121aa1709ca0f3246bcca37313dd09e032b0fef5dcd98f71997a8300b0e1bb",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-grow-direct-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-create-fast59",
            kind: "create-fast59",
            image: "symlink-b4096-grow-direct-before.raw",
            image_sha: "af121aa1709ca0f3246bcca37313dd09e032b0fef5dcd98f71997a8300b0e1bb",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-grow-direct-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-create-slow60",
            kind: "create-slow60",
            image: "symlink-b4096-grow-direct-before.raw",
            image_sha: "af121aa1709ca0f3246bcca37313dd09e032b0fef5dcd98f71997a8300b0e1bb",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-create-slowmax",
            kind: "create-slowmax",
            image: "symlink-b4096-grow-direct-before.raw",
            image_sha: "af121aa1709ca0f3246bcca37313dd09e032b0fef5dcd98f71997a8300b0e1bb",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-grow-direct-slowmax.bin",
            target_sha: "c3b9d3612f914704e2481c14ea12d442716643951b0da09957da441429f58ea1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b4096-grow-direct-before.raw",
            image_sha: "af121aa1709ca0f3246bcca37313dd09e032b0fef5dcd98f71997a8300b0e1bb",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b4096-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b4096-grow-direct-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b4096-grow-direct-before.raw",
            image_sha: "af121aa1709ca0f3246bcca37313dd09e032b0fef5dcd98f71997a8300b0e1bb",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b4096-grow-direct-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b4096-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b4096-grow-direct-before.raw",
            image_sha: "af121aa1709ca0f3246bcca37313dd09e032b0fef5dcd98f71997a8300b0e1bb",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b4096-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b4096-grow-direct-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b4096-grow-direct-before.raw",
            image_sha: "af121aa1709ca0f3246bcca37313dd09e032b0fef5dcd98f71997a8300b0e1bb",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b4096-grow-direct-slowmax.bin",
            old_sha: "c3b9d3612f914704e2481c14ea12d442716643951b0da09957da441429f58ea1",
            target: "target-b4096-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-rename-fast",
            kind: "rename-fast",
            image: "symlink-b4096-grow-direct-before.raw",
            image_sha: "af121aa1709ca0f3246bcca37313dd09e032b0fef5dcd98f71997a8300b0e1bb",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b4096-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-rename-slow",
            kind: "rename-slow",
            image: "symlink-b4096-grow-direct-before.raw",
            image_sha: "af121aa1709ca0f3246bcca37313dd09e032b0fef5dcd98f71997a8300b0e1bb",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b4096-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-unlink-alias-fast",
            kind: "unlink-alias-fast",
            image: "symlink-b4096-grow-direct-before.raw",
            image_sha: "af121aa1709ca0f3246bcca37313dd09e032b0fef5dcd98f71997a8300b0e1bb",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b4096-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-unlink-alias-slow",
            kind: "unlink-alias-slow",
            image: "symlink-b4096-grow-direct-before.raw",
            image_sha: "af121aa1709ca0f3246bcca37313dd09e032b0fef5dcd98f71997a8300b0e1bb",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b4096-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-unlink-final-fast59",
            kind: "unlink-final-fast59",
            image: "symlink-b4096-grow-direct-final-fast59.raw",
            image_sha: "1775422c1b8272439739c50254d1a57331daa8af60206cac3487a741fed4860b",
            source: "/symlink-fast59",
            alias: "",
            old_target: "target-b4096-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-unlink-final-slow60",
            kind: "unlink-final-slow60",
            image: "symlink-b4096-grow-direct-final-slow60.raw",
            image_sha: "db0663d4b13c4c631b98a7d09705f8288080e658059fc2563003375c10f5dded",
            source: "/symlink-slow60",
            alias: "",
            old_target: "target-b4096-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-no-free-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b4096-grow-direct-no-free.raw",
            image_sha: "03db9f756e8722ae8ccb8bb1ef6b29826fcfae1461272c4e470eb0aca8d00ca9",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b4096-grow-direct-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b4096-grow-direct-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-no-free-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b4096-grow-direct-no-free.raw",
            image_sha: "03db9f756e8722ae8ccb8bb1ef6b29826fcfae1461272c4e470eb0aca8d00ca9",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b4096-grow-direct-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b4096-grow-direct-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-no-free-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b4096-grow-direct-no-free.raw",
            image_sha: "03db9f756e8722ae8ccb8bb1ef6b29826fcfae1461272c4e470eb0aca8d00ca9",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b4096-grow-direct-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b4096-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-no-free-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b4096-grow-direct-no-free.raw",
            image_sha: "03db9f756e8722ae8ccb8bb1ef6b29826fcfae1461272c4e470eb0aca8d00ca9",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b4096-grow-direct-slowmax.bin",
            old_sha: "c3b9d3612f914704e2481c14ea12d442716643951b0da09957da441429f58ea1",
            target: "target-b4096-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-no-free-create-fast1",
            kind: "create-fast1",
            image: "symlink-b4096-grow-direct-no-free.raw",
            image_sha: "03db9f756e8722ae8ccb8bb1ef6b29826fcfae1461272c4e470eb0aca8d00ca9",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-grow-direct-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-direct-no-free-create-slow60",
            kind: "create-slow60",
            image: "symlink-b4096-grow-direct-no-free.raw",
            image_sha: "03db9f756e8722ae8ccb8bb1ef6b29826fcfae1461272c4e470eb0aca8d00ca9",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-grow-direct-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-create-fast1",
            kind: "create-fast1",
            image: "symlink-b4096-grow-indirect-before.raw",
            image_sha: "c8a54dce1750b2737b5b5b3b12168c80b01b3b3db104e2b2ae1e9c5b431bc024",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-grow-indirect-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-create-fast59",
            kind: "create-fast59",
            image: "symlink-b4096-grow-indirect-before.raw",
            image_sha: "c8a54dce1750b2737b5b5b3b12168c80b01b3b3db104e2b2ae1e9c5b431bc024",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-grow-indirect-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-create-slow60",
            kind: "create-slow60",
            image: "symlink-b4096-grow-indirect-before.raw",
            image_sha: "c8a54dce1750b2737b5b5b3b12168c80b01b3b3db104e2b2ae1e9c5b431bc024",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-create-slowmax",
            kind: "create-slowmax",
            image: "symlink-b4096-grow-indirect-before.raw",
            image_sha: "c8a54dce1750b2737b5b5b3b12168c80b01b3b3db104e2b2ae1e9c5b431bc024",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-grow-indirect-slowmax.bin",
            target_sha: "c3b9d3612f914704e2481c14ea12d442716643951b0da09957da441429f58ea1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b4096-grow-indirect-before.raw",
            image_sha: "c8a54dce1750b2737b5b5b3b12168c80b01b3b3db104e2b2ae1e9c5b431bc024",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b4096-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b4096-grow-indirect-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b4096-grow-indirect-before.raw",
            image_sha: "c8a54dce1750b2737b5b5b3b12168c80b01b3b3db104e2b2ae1e9c5b431bc024",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b4096-grow-indirect-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b4096-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b4096-grow-indirect-before.raw",
            image_sha: "c8a54dce1750b2737b5b5b3b12168c80b01b3b3db104e2b2ae1e9c5b431bc024",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b4096-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b4096-grow-indirect-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b4096-grow-indirect-before.raw",
            image_sha: "c8a54dce1750b2737b5b5b3b12168c80b01b3b3db104e2b2ae1e9c5b431bc024",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b4096-grow-indirect-slowmax.bin",
            old_sha: "c3b9d3612f914704e2481c14ea12d442716643951b0da09957da441429f58ea1",
            target: "target-b4096-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-rename-fast",
            kind: "rename-fast",
            image: "symlink-b4096-grow-indirect-before.raw",
            image_sha: "c8a54dce1750b2737b5b5b3b12168c80b01b3b3db104e2b2ae1e9c5b431bc024",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b4096-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-rename-slow",
            kind: "rename-slow",
            image: "symlink-b4096-grow-indirect-before.raw",
            image_sha: "c8a54dce1750b2737b5b5b3b12168c80b01b3b3db104e2b2ae1e9c5b431bc024",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b4096-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-unlink-alias-fast",
            kind: "unlink-alias-fast",
            image: "symlink-b4096-grow-indirect-before.raw",
            image_sha: "c8a54dce1750b2737b5b5b3b12168c80b01b3b3db104e2b2ae1e9c5b431bc024",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b4096-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-unlink-alias-slow",
            kind: "unlink-alias-slow",
            image: "symlink-b4096-grow-indirect-before.raw",
            image_sha: "c8a54dce1750b2737b5b5b3b12168c80b01b3b3db104e2b2ae1e9c5b431bc024",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b4096-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-unlink-final-fast59",
            kind: "unlink-final-fast59",
            image: "symlink-b4096-grow-indirect-final-fast59.raw",
            image_sha: "ebe254424b88bbba5ed600bb440dca823cb1c5773bd136e8f7c2594a66c1bcd5",
            source: "/symlink-fast59",
            alias: "",
            old_target: "target-b4096-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-unlink-final-slow60",
            kind: "unlink-final-slow60",
            image: "symlink-b4096-grow-indirect-final-slow60.raw",
            image_sha: "9b2f1e6ad122a23139ad70c23ba1d5c7c6bab347bbfc9909a600407c49f44077",
            source: "/symlink-slow60",
            alias: "",
            old_target: "target-b4096-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "",
            target_sha: "",
            destination: "/",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-no-free-replace-fast-fast",
            kind: "replace-fast-fast",
            image: "symlink-b4096-grow-indirect-no-free.raw",
            image_sha: "d7cfcf37c950ed037746e4b9361af6e028355a1bcf082ebe12263ef093bb74b9",
            source: "/symlink-fast59",
            alias: "/symlink-fast59-alias",
            old_target: "target-b4096-grow-indirect-fast59.bin",
            old_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            target: "target-b4096-grow-indirect-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-no-free-replace-slow-fast",
            kind: "replace-slow-fast",
            image: "symlink-b4096-grow-indirect-no-free.raw",
            image_sha: "d7cfcf37c950ed037746e4b9361af6e028355a1bcf082ebe12263ef093bb74b9",
            source: "/symlink-slow60",
            alias: "/symlink-slow60-alias",
            old_target: "target-b4096-grow-indirect-slow60.bin",
            old_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            target: "target-b4096-grow-indirect-fast59.bin",
            target_sha: "6cbf0d3c8a79c39608902b416dbc6b1d5447993340722153df1cfb3b60209e02",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: false,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-no-free-replace-fast-slow",
            kind: "replace-fast-slow",
            image: "symlink-b4096-grow-indirect-no-free.raw",
            image_sha: "d7cfcf37c950ed037746e4b9361af6e028355a1bcf082ebe12263ef093bb74b9",
            source: "/symlink-fast1",
            alias: "/symlink-fast1-alias",
            old_target: "target-b4096-grow-indirect-fast1.bin",
            old_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            target: "target-b4096-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-no-free-replace-slow-slow",
            kind: "replace-slow-slow",
            image: "symlink-b4096-grow-indirect-no-free.raw",
            image_sha: "d7cfcf37c950ed037746e4b9361af6e028355a1bcf082ebe12263ef093bb74b9",
            source: "/symlink-slowmax",
            alias: "/symlink-slowmax-alias",
            old_target: "target-b4096-grow-indirect-slowmax.bin",
            old_sha: "c3b9d3612f914704e2481c14ea12d442716643951b0da09957da441429f58ea1",
            target: "target-b4096-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-no-free-create-fast1",
            kind: "create-fast1",
            image: "symlink-b4096-grow-indirect-no-free.raw",
            image_sha: "d7cfcf37c950ed037746e4b9361af6e028355a1bcf082ebe12263ef093bb74b9",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-grow-indirect-fast1.bin",
            target_sha: "454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
        SymlinkCase {
            bs: 4096,
            operation: "symlink-grow-indirect-no-free-create-slow60",
            kind: "create-slow60",
            image: "symlink-b4096-grow-indirect-no-free.raw",
            image_sha: "d7cfcf37c950ed037746e4b9361af6e028355a1bcf082ebe12263ef093bb74b9",
            source: "",
            alias: "",
            old_target: "",
            old_sha: "",
            target: "target-b4096-grow-indirect-slow60.bin",
            target_sha: "05d37174fe280c1c9f2c044128f3e248f1a73a9283e38f9ea59fdca35675cbcb",
            destination: "/crowded/target-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            refuse: true,
        },
    ]
}
fn symlink_path(path: &str) -> Vec<NativeName> {
    path.as_bytes()
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .map(|p| NativeName::Bytes(p.to_vec()))
        .collect()
}
fn symlink_split(path: &str) -> (Vec<NativeName>, Vec<u8>) {
    let mut parts = symlink_path(path);
    let NativeName::Bytes(name) = parts.pop().unwrap() else {
        unreachable!()
    };
    (parts, name)
}
fn symlink_operation(
    owner: &mut crate::fs_ext::ExtJournalSession<Model>,
    c: &SymlinkCase,
    target: &[u8],
    r: &Resources,
) -> io::Result<()> {
    let (source_parent, source_name) = if c.source.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        symlink_split(c.source)
    };
    let (parent, name) = if c.destination == "/" {
        (Vec::new(), Vec::new())
    } else {
        symlink_split(c.destination)
    };
    if c.kind.starts_with("create-") {
        owner.create_symlink(
            &parent,
            &name,
            target,
            &crate::fs_ext_edit::ExtCreateMetadata::zeroed(0xa1ff),
            planning(),
            &r.cancellation,
        )
    } else if c.kind.starts_with("replace-") {
        owner.replace_symlink_target(
            &source_parent,
            &source_name,
            target,
            planning(),
            &r.cancellation,
        )
    } else if c.kind.starts_with("rename-") {
        owner.rename(
            &source_parent,
            &source_name,
            &parent,
            &name,
            planning(),
            &r.cancellation,
        )
    } else {
        let (p, n) = symlink_split(if c.kind.starts_with("unlink-alias-") {
            c.alias
        } else {
            c.source
        });
        owner.unlink_symlink(&p, &n, 946684800, planning(), &r.cancellation)
    }
}
fn symlink_contents(
    owner: &crate::fs_ext::ExtJournalSession<Model>,
    c: &SymlinkCase,
    old_target: &[u8],
    target: &[u8],
    new: bool,
    r: &Resources,
) {
    let observe = |path: &str, expected: Option<&[u8]>| {
        if path.is_empty() {
            return;
        }
        let result = owner.read_symlink(&symlink_path(path), &r.cancellation);
        match expected {
            Some(bytes) => {
                let actual = result.unwrap();
                assert_eq!(actual.as_slice(), bytes, "{} {path}", c.operation)
            }
            None => assert!(result.is_err(), "unexpected symlink {} {path}", c.operation),
        }
    };
    if c.kind.starts_with("create-") {
        observe(c.destination, new.then_some(target));
    } else if c.kind.starts_with("replace-") {
        observe(c.source, Some(if new { target } else { old_target }));
        observe(c.alias, Some(if new { target } else { old_target }));
    } else if c.kind.starts_with("rename-") {
        observe(c.source, (!new).then_some(old_target));
        observe(c.destination, new.then_some(old_target));
        observe(c.alias, Some(old_target));
    } else if c.kind.starts_with("unlink-alias-") {
        observe(c.source, Some(old_target));
        observe(c.alias, (!new).then_some(old_target));
    } else {
        observe(c.source, (!new).then_some(old_target));
    }
}

#[test]
#[ignore = "requires pinned symlink corpus, fresh evidence and independent native verification"]
fn native_owned_ext3_ordered_symlink_cuts() {
    let corpus = required("PARTMGR_EXT_SYMLINK_CORPUS");
    let root = required("PARTMGR_GATE_SOURCE_ROOT");
    let out = required("PARTMGR_EXT_SYMLINK_EVIDENCE");
    fs::create_dir(&out).unwrap();
    fs::create_dir(out.join("images")).unwrap();
    let receipt = checked(
        &corpus.join("receipt.json"),
        "661553227d2108ed7d10adc22213f76053d314f1c3754bb70d6297275fe66ee5",
    );
    fs::write(out.join("fixture-receipt.json"), receipt).unwrap();
    let snapshot = || {
        let mut manifest = String::new();
        for (name, bytes) in compiled_sources() {
            assert_eq!(fs::read(root.join(name)).unwrap(), *bytes);
            writeln!(manifest, "{}  {name}", hash(bytes)).unwrap();
        }
        manifest
    };
    let before = snapshot();
    fs::write(out.join("source-start.sha256"), &before).unwrap();
    for (name, bytes) in compiled_sources() {
        let path = out.join("compiled-source").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fs::write(
        out.join("gate-binary"),
        fs::read(std::env::current_exe().unwrap()).unwrap(),
    )
    .unwrap();
    let mut manifest = String::from(
        "bs\toperation\tcase\tevent\tmodel\tfault_kind\tprefix\tpre_sha256\tpre_path\tretried_sha256\tretried_path\tresult\n",
    );
    let mut observations = String::new();
    let mut errors = String::new();
    let mut total = 0usize;
    let mut enospc =
        String::from("bs\toperation\tsource_sha256\tafter_sha256\twrites\tflushes\terror\n");
    assert_eq!(symlink_cases().len(), 180);
    for c in symlink_cases() {
        let bs = c.bs;
        let operation = c.operation;
        let original = checked(&corpus.join(c.image), c.image_sha);
        let target = if c.target.is_empty() {
            Vec::new()
        } else {
            checked(&corpus.join(c.target), c.target_sha)
        };
        let old_target = if c.old_target.is_empty() {
            Vec::new()
        } else {
            checked(&corpus.join(c.old_target), c.old_sha)
        };
        let mutate = |owner: &mut crate::fs_ext::ExtJournalSession<Model>, r: &Resources| {
            symlink_operation(owner, c, &target, r)
        };
        let contents =
            |owner: &crate::fs_ext::ExtJournalSession<Model>, new: bool, r: &Resources| {
                symlink_contents(owner, c, &old_target, &target, new, r)
            };
        if c.refuse {
            let r = resources();
            let mut owner =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            contents(&owner, false, &r);
            let error = mutate(&mut owner, &r).unwrap_err();
            let (model, state) = owner.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            assert!(model.trace.is_empty());
            assert_eq!(model.visible, original);
            assert_eq!(model.durable, original);
            assert!(format!("{error:?}").contains("InvalidOperation"));
            assert!(
                error
                    .to_string()
                    .contains("ext2 no audited free blocks available"),
                "unexpected refusal {operation}: {error:?}"
            );
            writeln!(errors, "bs={bs} operation={operation} refusal={error:?}").unwrap();
            writeln!(
                enospc,
                "{bs}\t{operation}\t{}\t{}\t0\t0\tInvalidOperation:no-audited-free-blocks",
                c.image_sha,
                hash(&model.visible)
            )
            .unwrap();
            assert_eq!(r.memory.used(), 0);
            continue;
        }
        let r = resources();
        let boot =
            bootstrap::Bootstrap::read(&Model::new(&original), 65536, 32_000_000, &r).unwrap();
        let journal = boot.physical_blocks.clone();
        drop(boot);
        assert_eq!(r.memory.used(), 0);
        fs::write(
            out.join(format!("journal-map-b{bs}.tsv")),
            journal.iter().map(|n| format!("{n}\n")).collect::<String>(),
        )
        .unwrap();
        {
            let r = resources();
            let mut baseline =
                crate::fs_ext::ExtJournalSession::open(Model::new(&original), public_limits(), &r)
                    .unwrap();
            contents(&baseline, false, &r);
            mutate(&mut baseline, &r).unwrap();
            contents(&baseline, true, &r);
            let (baseline, state) = baseline.into_storage();
            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
            assert_eq!(baseline.visible, baseline.durable);
            let trace = baseline.trace.clone();
            let expected = baseline.visible;
            symlink_regular_unchanged(&original, &expected, bs);
            assert!(!home_equal(&original, &expected, bs, &journal));
            let (h, path) = saved(&out, &expected);
            writeln!(
                observations,
                "bs={bs} operation={operation} events={} baseline={path}",
                trace.len()
            )
            .unwrap();
            assert_eq!(path, format!("images/{h}.raw"));
            let mut events = String::from("event\tkind\tbytes\n");
            for (i, event) in trace.iter().enumerate() {
                match event {
                    Event::Write(n) => writeln!(events, "{}\twrite\t{n}", i + 1).unwrap(),
                    Event::Flush => writeln!(events, "{}\tflush\t0", i + 1).unwrap(),
                }
            }
            fs::write(out.join(format!("events-b{bs}-{operation}.tsv")), events).unwrap();
            assert_eq!(r.memory.used(), 0);
            let mut case = 0usize;
            for (event, kind) in trace.iter().enumerate() {
                let prefixes = match kind {
                    Event::Write(n) => vec![0, n / 2, *n],
                    Event::Flush => vec![0],
                };
                for immediate in [false, true] {
                    for persist in [false, true] {
                        for prefix in &prefixes {
                            case += 1;
                            total += 1;
                            let r = resources();
                            let mut model = Model::new(&original);
                            model.cut = event + 1;
                            model.prefix = *prefix;
                            model.immediate = immediate;
                            model.persist = persist;
                            let mut owner =
                                crate::fs_ext::ExtJournalSession::open(model, public_limits(), &r)
                                    .unwrap();
                            let error = mutate(&mut owner, &r).unwrap_err();
                            writeln!(
                                errors,
                                "bs={bs} operation={operation} case={case} error={error:?}"
                            )
                            .unwrap();
                            assert!(error.to_string().contains("owned native cut"));
                            let (model, state) = owner.into_storage();
                            assert!(model.hit);
                            assert_eq!(state, crate::fs_ext::ExtJournalState::NeedsRecovery);
                            let (prehash, prepath) = saved(&out, &model.durable);
                            let mut cold = crate::fs_ext::ExtJournalSession::open_for_recovery(
                                Model::new(&model.durable),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            cold.recover(&r.cancellation).unwrap();
                            let (recovered, state) = cold.into_storage();
                            assert_eq!(state, crate::fs_ext::ExtJournalState::Ready);
                            assert_eq!(recovered.visible, recovered.durable);
                            symlink_regular_unchanged(&original, &recovered.visible, bs);
                            let old = home_equal(&recovered.visible, &original, bs, &journal);
                            let new = home_equal(&recovered.visible, &expected, bs, &journal);
                            assert_ne!(
                                old,
                                new,
                                "namespace partial outcome {bs} {operation} event={} prefix={prefix}",
                                event + 1
                            );
                            let result = if old { "old" } else { "new" };
                            let check = crate::fs_ext::ExtJournalSession::open(
                                Model::new(&recovered.visible),
                                public_limits(),
                                &r,
                            )
                            .unwrap();
                            contents(&check, new, &r);
                            drop(check);
                            let (retryhash, retrypath) = saved(&out, &recovered.visible);
                            writeln!(manifest,"{bs}\t{operation}\t{case}\t{}\t{}\t{}\t{prefix}\t{prehash}\t{prepath}\t{retryhash}\t{retrypath}\t{result}",event+1,if immediate{"immediate"}else{"volatile"},match kind{Event::Write(_)=>"write",Event::Flush=>if persist{"flush-persist"}else{"flush-none"}}).unwrap();
                            assert_eq!(r.memory.used(), 0);
                        }
                    }
                }
            }
        }
        checked(&corpus.join(c.image), c.image_sha);
        if !c.target.is_empty() {
            checked(&corpus.join(c.target), c.target_sha);
        }
        if !c.old_target.is_empty() {
            checked(&corpus.join(c.old_target), c.old_sha);
        }
    }
    // Revalidate even refusal bindings: the early continue must not skip final guards.
    for c in symlink_cases() {
        checked(&corpus.join(c.image), c.image_sha);
        if !c.target.is_empty() {
            checked(&corpus.join(c.target), c.target_sha);
        }
        if !c.old_target.is_empty() {
            checked(&corpus.join(c.old_target), c.old_sha);
        }
    }
    assert_eq!(snapshot(), before);
    fs::write(out.join("source-end.sha256"), snapshot()).unwrap();
    fs::write(out.join("namespace-cuts.tsv"), manifest).unwrap();
    fs::write(out.join("observations.txt"), observations).unwrap();
    fs::write(out.join("cut-errors.txt"), errors).unwrap();
    checked(
        &corpus.join("receipt.json"),
        "661553227d2108ed7d10adc22213f76053d314f1c3754bb70d6297275fe66ee5",
    );
    fs::write(out.join("enospc.tsv"), enospc).unwrap();
    fs::write(out.join("report.txt"),format!("complete=true\ncases={total}\nscope=public classic symlink modeled cuts, all180 receipt cases, slow target metadata WAL, exact OLD/NEW homes; independent native verification required; offline modeled qualification only; no kernel or hardware crash claim\n")).unwrap();
}
