//! Independent working-file guards and private generic storage fault models.
use super::*;
use crate::fs_core::{Budget, Cancellation};
use std::cell::Cell;
fn resources() -> Resources {
    Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> ExtFormatLimits {
    ExtFormatLimits {
        zero_scan_bytes: 16 << 20,
        build: ExtBuildLimits {
            objects: 4,
            links: 4,
            name_bytes: 1024,
            blocks: 32768,
            work: 4_000_000,
            depth: 8,
        },
        audit: ExtAuditLimits {
            blocks: 32768,
            inodes: 32768,
            work: 8_000_000,
            directory_blocks: 1024,
            directory_entries: 1024,
            findings: 64,
        },
    }
}
fn options() -> ExtBuildOptions {
    ExtBuildOptions {
        block_size: 1024,
        blocks_per_group: 8192,
        uuid: [0x39; 16],
    }
}
fn metadata() -> ExtBuildMetadata {
    ExtBuildMetadata {
        file_permissions: 0o644,
        directory_permissions: 0o755,
        uid: 0,
        gid: 0,
        timestamp: 946684800,
    }
}
fn path(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "partmgr-format-draft-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    root.join("output.working")
}
#[test]
fn existing_output_unchanged() {
    let p = path("existing");
    std::fs::write(&p, b"preserve").unwrap();
    assert!(ExtFormatImage::create_new(&p, 16 << 20, &resources()).is_err());
    assert_eq!(std::fs::read(p).unwrap(), b"preserve");
}
#[cfg(unix)]
#[test]
fn symlink_output_rejected() {
    let p = path("symlink");
    let target = p.with_extension("target");
    std::fs::write(&target, b"preserve").unwrap();
    std::os::unix::fs::symlink(&target, &p).unwrap();
    assert!(ExtFormatImage::create_new(&p, 16 << 20, &resources()).is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"preserve");
}
#[test]
fn changed_actual_output_terminal() {
    let p = path("changed");
    let mut image = ExtFormatImage::create_new(&p, 16 << 20, &resources()).unwrap();
    image.core.file.write_at(0, &[1]).unwrap();
    let r = resources();
    assert!(
        image
            .plan_empty(options(), metadata(), limits(), &r)
            .unwrap()
            .emit(&r)
            .is_err()
    );
    assert_eq!(image.state(), ExtFormatState::Failed);
    assert!(image.into_verified().is_err());
    assert_eq!(std::fs::read(p).unwrap()[0], 1);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn cancellation_terminal_and_unpublished() {
    let p = path("cancel");
    let mut image = ExtFormatImage::create_new(&p, 16 << 20, &resources()).unwrap();
    let r = resources();
    let plan = image
        .plan_empty(options(), metadata(), limits(), &r)
        .unwrap();
    r.cancellation.cancel();
    assert!(plan.emit(&r).is_err());
    assert_eq!(image.state(), ExtFormatState::Failed);
    assert!(image.into_verified().is_err());
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn dropped_plan_permits_new_plan_without_writes() {
    let p = path("drop");
    let mut image = ExtFormatImage::create_new(&p, 16 << 20, &resources()).unwrap();
    let r = resources();
    drop(
        image
            .plan_empty(options(), metadata(), limits(), &r)
            .unwrap(),
    );
    assert_eq!(image.state(), ExtFormatState::Empty);
    assert_eq!(r.memory.used(), 0);
}

#[derive(Clone, Copy)]
enum Failure {
    Zero,
    Short,
    Excess,
    ZeroRead,
    Length,
    Audit,
    Write,
    Flush(bool),
    Readback,
    Cancel,
}
struct Fault {
    visible: Vec<u8>,
    durable: Vec<u8>,
    writes: usize,
    flushes: usize,
    failure: Failure,
    cancellation: Cancellation,
    reads: Cell<usize>,
    lens: Cell<usize>,
}
impl Storage for Fault {
    fn len(&self) -> io::Result<u64> {
        self.lens.set(self.lens.get() + 1);
        Ok(self.visible.len() as u64
            + u64::from(matches!(self.failure, Failure::Length) && self.lens.get() > 1))
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.set(self.reads.get() + 1);
        if matches!(self.failure, Failure::ZeroRead) && self.writes == 0 {
            return Err(io::Error::other("independent zero scan read cause"));
        }
        if matches!(self.failure, Failure::Audit) && self.flushes > 0 && self.reads.get() > 512 {
            return Err(io::Error::other("independent final audit cause"));
        }
        out.copy_from_slice(&self.visible[at as usize..at as usize + out.len()]);
        if self.writes > 0 && matches!(self.failure, Failure::Readback) {
            return Err(io::Error::other("independent postwrite read cause"));
        }
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if matches!(self.failure, Failure::Zero) {
            return Ok(0);
        }
        if matches!(self.failure, Failure::Excess) {
            return Ok(bytes.len() + 1);
        }
        if matches!(self.failure, Failure::Short) {
            let n = bytes.len().min(17);
            self.visible[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            return Ok(n);
        }
        let n = if matches!(self.failure, Failure::Write) {
            bytes.len().min(1073)
        } else {
            bytes.len()
        };
        self.visible[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
        if matches!(self.failure, Failure::Write) {
            return Err(io::Error::other("independent partial write cause"));
        }
        if matches!(self.failure, Failure::Cancel) {
            self.cancellation.cancel();
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if !matches!(self.failure, Failure::Flush(false)) {
            self.durable.clone_from(&self.visible);
        }
        if matches!(self.failure, Failure::Flush(_)) {
            return Err(io::Error::other("independent failed flush cause"));
        }
        Ok(())
    }
}
#[test]
fn actual_write_attempt_wraps_cause_and_is_terminal() {
    for failure in [
        Failure::Zero,
        Failure::Excess,
        Failure::Audit,
        Failure::Write,
        Failure::Flush(false),
        Failure::Flush(true),
        Failure::Readback,
        Failure::Cancel,
    ] {
        let r = resources();
        let fault = Fault {
            visible: vec![0; 16 << 20],
            durable: vec![0; 16 << 20],
            writes: 0,
            flushes: 0,
            failure,
            cancellation: r.cancellation.clone(),
            reads: Cell::new(0),
            lens: Cell::new(0),
        };
        let mut core = Core {
            file: Tracking {
                backend: fault,
                attempted_write: false,
            },
            length: 16 << 20,
            state: ExtFormatState::Empty,
        };
        let error = core
            .plan_empty(options(), metadata(), limits(), &r)
            .unwrap()
            .emit(&r)
            .err()
            .unwrap();
        assert_eq!(
            error.kind,
            if matches!(failure, Failure::Flush(_)) {
                ErrorKind::UncertainDurability
            } else {
                ErrorKind::InterruptedWrite
            }
        );
        assert_eq!(core.state, ExtFormatState::Failed);
        assert!(core.file.attempted_write);
        assert!(
            core.plan_empty(options(), metadata(), limits(), &resources())
                .is_err()
        );
        assert_eq!(r.memory.used(), 0);
        if matches!(failure, Failure::Cancel) {
            assert!(cause_has_kind(&error, ErrorKind::Cancelled));
        }
        if matches!(failure, Failure::Write) {
            assert!(cause_has_text(&error, "independent partial write cause"));
            assert!(core.file.backend.visible.iter().any(|b| *b != 0));
        }
        if matches!(failure, Failure::Flush(false)) {
            assert!(core.file.backend.durable.iter().all(|b| *b == 0));
        }
        if matches!(failure, Failure::Flush(true) | Failure::Readback) {
            assert_ne!(core.file.backend.durable, vec![0; 16 << 20]);
        }
    }
}
#[test]
fn cancellation_before_backend_write_retains_original_category() {
    let r = resources();
    let fault = Fault {
        visible: vec![0; 16 << 20],
        durable: vec![0; 16 << 20],
        writes: 0,
        flushes: 0,
        failure: Failure::Write,
        cancellation: r.cancellation.clone(),
        reads: Cell::new(0),
        lens: Cell::new(0),
    };
    let mut core = Core {
        file: Tracking {
            backend: fault,
            attempted_write: false,
        },
        length: 16 << 20,
        state: ExtFormatState::Empty,
    };
    let plan = core
        .plan_empty(options(), metadata(), limits(), &r)
        .unwrap();
    r.cancellation.cancel();
    let error = plan.emit(&r).err().unwrap();
    assert_ne!(error.kind, ErrorKind::InterruptedWrite);
    assert!(!core.file.attempted_write);
    assert_eq!(core.file.backend.writes, 0);
    assert_eq!(core.state, ExtFormatState::Failed);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn prewrite_failures_keep_category_and_zero_bytes() {
    for failure in [Failure::ZeroRead, Failure::Length] {
        let r = resources();
        let fault = Fault {
            visible: vec![0; 16 << 20],
            durable: vec![0; 16 << 20],
            writes: 0,
            flushes: 0,
            failure,
            cancellation: r.cancellation.clone(),
            reads: Cell::new(0),
            lens: Cell::new(0),
        };
        let mut core = Core {
            file: Tracking {
                backend: fault,
                attempted_write: false,
            },
            length: 16 << 20,
            state: ExtFormatState::Empty,
        };
        let error = core
            .plan_empty(options(), metadata(), limits(), &r)
            .unwrap()
            .emit(&r)
            .err()
            .unwrap();
        assert_ne!(error.kind, ErrorKind::InterruptedWrite);
        assert_eq!(core.state, ExtFormatState::Failed);
        assert!(!core.file.attempted_write);
        assert_eq!(core.file.backend.writes, 0);
        assert!(core.file.backend.visible.iter().all(|b| *b == 0));
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn short_writes_complete_and_verify() {
    let r = resources();
    let fault = Fault {
        visible: vec![0; 16 << 20],
        durable: vec![0; 16 << 20],
        writes: 0,
        flushes: 0,
        failure: Failure::Short,
        cancellation: r.cancellation.clone(),
        reads: Cell::new(0),
        lens: Cell::new(0),
    };
    let mut core = Core {
        file: Tracking {
            backend: fault,
            attempted_write: false,
        },
        length: 16 << 20,
        state: ExtFormatState::Empty,
    };
    let report = core
        .plan_empty(options(), metadata(), limits(), &r)
        .unwrap()
        .emit(&r)
        .unwrap();
    assert!(report.audit.is_clean());
    assert_eq!(core.state, ExtFormatState::Verified);
    assert_eq!(core.file.backend.visible, core.file.backend.durable);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn constructor_budget_rejects_before_creating_path() {
    let p = path("constructor-budget");
    let r = Resources {
        memory: Budget::new(0),
        cancellation: Cancellation::default(),
    };
    assert!(ExtFormatImage::create_new(&p, 16 << 20, &r).is_err());
    assert!(!p.exists());
    assert_eq!(r.memory.used(), 0);
}

fn cause_has_kind(error: &(dyn std::error::Error + 'static), kind: ErrorKind) -> bool {
    if error
        .downcast_ref::<Error>()
        .is_some_and(|e| e.kind == kind)
    {
        return true;
    }
    if let Some(io) = error.downcast_ref::<io::Error>()
        && io.get_ref().is_some_and(|e| cause_has_kind(e, kind))
    {
        return true;
    }
    error.source().is_some_and(|e| cause_has_kind(e, kind))
}
fn cause_has_text(error: &(dyn std::error::Error + 'static), text: &str) -> bool {
    if error.to_string() == text {
        return true;
    }
    if let Some(io) = error.downcast_ref::<io::Error>()
        && io.get_ref().is_some_and(|e| cause_has_text(e, text))
    {
        return true;
    }
    error.source().is_some_and(|e| cause_has_text(e, text))
}
#[derive(Clone, Copy)]
enum MatrixCut {
    None,
    Write(usize, usize),
    Flush(usize, bool),
    Read(usize),
    CancelWrite(usize),
    CancelRead(usize),
}
struct Matrix {
    immediate: bool,
    visible: Vec<u8>,
    durable: Vec<u8>,
    writes: usize,
    flushes: usize,
    reads: Cell<usize>,
    cut: MatrixCut,
    cancellation: Cancellation,
    hit: Cell<bool>,
}
impl Storage for Matrix {
    fn len(&self) -> io::Result<u64> {
        Ok(self.visible.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let n = self.reads.get() + 1;
        self.reads.set(n);
        if matches!(self.cut,MatrixCut::Read(i) if i==n) {
            self.hit.set(true);
            return Err(io::Error::other("matrix read sentinel"));
        }
        out.copy_from_slice(&self.visible[at as usize..at as usize + out.len()]);
        if matches!(self.cut,MatrixCut::CancelRead(i) if i==n) {
            self.hit.set(true);
            self.cancellation.cancel();
        }
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if let MatrixCut::Write(i, prefix) = self.cut
            && i == self.writes
        {
            self.hit.set(true);
            let n = prefix.min(bytes.len());
            self.visible[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            if self.immediate {
                self.durable[at as usize..at as usize + n].copy_from_slice(&bytes[..n]);
            }
            return Err(io::Error::other("matrix write sentinel"));
        }
        self.visible[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        if self.immediate {
            self.durable[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        }
        if matches!(self.cut,MatrixCut::CancelWrite(i) if i==self.writes) {
            self.hit.set(true);
            self.cancellation.cancel();
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if let MatrixCut::Flush(i, persist) = self.cut
            && i == self.flushes
        {
            self.hit.set(true);
            if persist {
                self.durable.clone_from(&self.visible);
            }
            return Err(io::Error::other("matrix flush sentinel"));
        }
        self.durable.clone_from(&self.visible);
        Ok(())
    }
}
fn matrix_core(cut: MatrixCut, immediate: bool, r: &Resources) -> Core<Matrix> {
    Core {
        file: Tracking {
            backend: Matrix {
                immediate,
                visible: vec![0; 1 << 20],
                durable: vec![0; 1 << 20],
                writes: 0,
                flushes: 0,
                reads: Cell::new(0),
                cut,
                cancellation: r.cancellation.clone(),
                hit: Cell::new(false),
            },
            attempted_write: false,
        },
        length: 1 << 20,
        state: ExtFormatState::Empty,
    }
}
#[test]
fn every_backend_boundary_is_terminal_on_failure_for_all_block_profiles() {
    let started = std::time::Instant::now();
    let mut cases = 0;
    for bs in [1024, 2048, 4096] {
        let mut native = options();
        native.block_size = bs;
        let r = resources();
        let mut baseline = matrix_core(MatrixCut::None, false, &r);
        let report = baseline
            .plan_empty(native, metadata(), limits(), &r)
            .unwrap()
            .emit(&r)
            .unwrap();
        assert!(report.audit.is_clean());
        drop(report);
        let counts = (
            baseline.file.backend.writes,
            baseline.file.backend.flushes,
            baseline.file.backend.reads.get(),
        );
        assert_eq!(counts.0, 16);
        assert_eq!(counts.1, 1);
        assert!(counts.2 > 32);
        assert_eq!(r.memory.used(), 0);
        let mut cuts = Vec::new();
        for i in 1..=counts.0 {
            for prefix in [0, 1073, 65536] {
                cuts.push(MatrixCut::Write(i, prefix));
            }
            cuts.push(MatrixCut::CancelWrite(i));
        }
        for i in 1..=counts.1 {
            cuts.extend([MatrixCut::Flush(i, false), MatrixCut::Flush(i, true)]);
        }
        for i in 1..=counts.2 {
            cuts.extend([MatrixCut::Read(i), MatrixCut::CancelRead(i)]);
        }
        for immediate in [false, true] {
            for cut in &cuts {
                let cut = *cut;
                cases += 1;
                let r = resources();
                let mut core = matrix_core(cut, immediate, &r);
                let error = core
                    .plan_empty(native, metadata(), limits(), &r)
                    .unwrap()
                    .emit(&r)
                    .err()
                    .expect("injected cut must fail");
                assert!(core.file.backend.hit.get());
                assert_eq!(core.state, ExtFormatState::Failed);
                assert!(
                    core.plan_empty(native, metadata(), limits(), &resources())
                        .is_err()
                );
                match cut {
                    MatrixCut::Flush(_, _) => {
                        assert_eq!(error.kind, ErrorKind::UncertainDurability);
                        assert!(cause_has_text(&error, "matrix flush sentinel"));
                    }
                    MatrixCut::Write(i, prefix) => {
                        assert_eq!(error.kind, ErrorKind::InterruptedWrite);
                        assert!(cause_has_text(&error, "matrix write sentinel"));
                        if i == 1 && prefix >= 1073 {
                            assert!(core.file.backend.visible.iter().any(|b| *b != 0));
                        }
                    }
                    MatrixCut::Read(_) => {
                        assert!(cause_has_text(&error, "matrix read sentinel"));
                        assert_eq!(
                            error.kind,
                            if core.file.attempted_write {
                                ErrorKind::InterruptedWrite
                            } else {
                                ErrorKind::Io
                            }
                        );
                    }
                    MatrixCut::CancelWrite(_) | MatrixCut::CancelRead(_) => {
                        assert!(cause_has_kind(&error, ErrorKind::Cancelled));
                        assert_eq!(
                            error.kind,
                            if core.file.attempted_write {
                                ErrorKind::InterruptedWrite
                            } else {
                                ErrorKind::Cancelled
                            }
                        );
                    }
                    MatrixCut::None => unreachable!(),
                }
                let emitted = match cut {
                    MatrixCut::Write(i, prefix) => (i - 1) * 65536 + prefix.min(65536),
                    MatrixCut::CancelWrite(i) => i * 65536,
                    _ if core.file.attempted_write => 1 << 20,
                    _ => 0,
                };
                assert_eq!(
                    &core.file.backend.visible[..emitted],
                    &baseline.file.backend.visible[..emitted]
                );
                assert!(core.file.backend.visible[emitted..].iter().all(|b| *b == 0));
                if immediate {
                    assert_eq!(core.file.backend.durable, core.file.backend.visible);
                } else if core.file.backend.flushes == 0
                    || matches!(cut, MatrixCut::Flush(_, false))
                {
                    assert!(core.file.backend.durable.iter().all(|b| *b == 0));
                } else {
                    assert_eq!(core.file.backend.durable, baseline.file.backend.durable);
                }
                assert_eq!(r.memory.used(), 0);
            }
        }
        eprintln!(
            "ext format matrix blocksize={bs} writes={} flushes={} reads={}",
            counts.0, counts.1, counts.2
        );
    }
    eprintln!(
        "ext format matrix cases={cases} elapsed={:?}",
        started.elapsed()
    );
}
