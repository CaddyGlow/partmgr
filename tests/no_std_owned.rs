//! Execute allocation-only owned discovery with storage that cannot cross threads.
#![cfg(not(feature = "std"))]
use partmgr::{
    fs_apfs::ApfsReadLimits,
    fs_apfs_audit::ApfsAuditLimits,
    fs_apfs_edit::{ApfsEditLimits, ApfsEditor},
    fs_core::{Budget, Cancellation, ErrorKind, NativeName, Resources, StreamKind},
    fs_hfsplus::{
        HfsPlusReadLimits,
        edit::{HfsPlusEditLimits, HfsPlusEditSession},
    },
    fs_hfsplus_audit::HfsPlusAuditLimits,
    fs_undo::UndoLimits,
    io,
    storage::Storage,
};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
#[allow(dead_code)]
#[path = "fixtures/apfs_clean.rs"]
mod apfs;
#[allow(dead_code)]
#[path = "fixtures/hfsplus_clean.rs"]
mod hfsplus;
struct Owner {
    bytes: Rc<RefCell<Vec<u8>>>,
    reads: Rc<Cell<usize>>,
}
impl Owner {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Rc::new(RefCell::new(bytes)),
            reads: Rc::new(Cell::new(0)),
        }
    }
}
impl Storage for Owner {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.borrow().len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.set(self.reads.get() + 1);
        let at = usize::try_from(at).map_err(io::Error::other)?;
        let end = at
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(
            self.bytes
                .borrow()
                .get(at..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        panic!("preparation and planning must not write")
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("preparation and planning must not flush")
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(256 << 20),
        cancellation: Cancellation::default(),
    }
}
fn apfs_limits() -> ApfsEditLimits {
    ApfsEditLimits {
        metadata_blocks: 64,
        attempts: 65,
        work: 16 << 30,
        read: ApfsReadLimits {
            blocks: 512,
            checkpoint_blocks: 8,
            objects: 256,
            records: 256,
            work: 64 << 20,
        },
        audit: ApfsAuditLimits {
            blocks: 512,
            objects: 512,
            depth: 32,
            work: 64 << 20,
            findings: 64,
        },
    }
}
fn hfsplus_limits() -> HfsPlusEditLimits {
    HfsPlusEditLimits {
        pages: 256,
        attempts: 257,
        work: 1 << 36,
        range_bytes: 1 << 16,
        read: HfsPlusReadLimits {
            blocks: 65536,
            nodes: 4096,
            records: 512,
            extents: 2048,
            work: 16 << 20,
        },
        audit: HfsPlusAuditLimits {
            blocks: 65536,
            objects: 512,
            depth: 32,
            work: 1_000_000,
            findings: 64,
        },
        undo: UndoLimits {
            patches: 16,
            body_bytes: 1 << 15,
        },
    }
}
#[test]
fn apfs_owned_alloc_discovery_audits_without_mutating_non_send_storage() {
    let r = resources();
    let original = apfs::apfs_seed();
    let owner = Owner::new(original.clone());
    let bytes = owner.bytes.clone();
    let reads = owner.reads.clone();
    let session = ApfsEditor::open(owner, 1026, apfs_limits(), &r).unwrap();
    assert!(session.allocation_proof().is_complete());
    assert!(session.allocation_proof().is_clean());
    assert!(session.copied_metadata_blocks() > 1);
    assert!(reads.get() >= session.copied_metadata_blocks());
    let decoder_charge = apfs_limits().read.work + apfs_limits().audit.work;
    assert!(session.work_used() >= decoder_charge * (session.copied_metadata_blocks() as u64 + 2));
    session.revalidate(&r).unwrap();
    assert_eq!(*bytes.borrow(), original);
    drop(session.into_storage());
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn hfsplus_owned_alloc_discovery_supports_native_range_planning_and_refunds() {
    for binary in [false, true] {
        let r = resources();
        let original = hfsplus::hfsplus_seed(binary);
        let owner = Owner::new(original.clone());
        let bytes = owner.bytes.clone();
        let reads = owner.reads.clone();
        let session = HfsPlusEditSession::open(owner, hfsplus_limits(), &r).unwrap();
        assert!(reads.get() > 1);
        assert!(!session.needs_recovery());
        let path = [NativeName::Utf16(hfsplus::native_name(binary))];
        let plan = session
            .plan_range(&path, &StreamKind::Data, 32760, &[0x5a; 31], &r)
            .unwrap();
        assert_eq!(*bytes.borrow(), original);
        drop(plan);
        drop(session.into_storage());
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn owned_alloc_preparation_work_caps_reject_before_backend_reads() {
    let r = resources();
    let owner = Owner::new(apfs::apfs_seed());
    let reads = owner.reads.clone();
    let mut limits = apfs_limits();
    limits.work = 1;
    let error = match ApfsEditor::open(owner, 1026, limits, &r) {
        Ok(_) => panic!("accepted work cap"),
        Err(e) => e,
    };
    assert_eq!(error.kind, ErrorKind::BudgetExhausted);
    assert_eq!(reads.get(), 0);
    assert_eq!(r.memory.used(), 0);
    let owner = Owner::new(hfsplus::hfsplus_seed(false));
    let reads = owner.reads.clone();
    let mut limits = hfsplus_limits();
    limits.work = 1;
    let error = match HfsPlusEditSession::open(owner, limits, &r) {
        Ok(_) => panic!("accepted work cap"),
        Err(e) => e,
    };
    assert_eq!(error.kind, ErrorKind::BudgetExhausted);
    assert_eq!(reads.get(), 0);
    assert_eq!(r.memory.used(), 0);
}
