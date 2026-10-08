#![cfg(feature = "std")]

use partmgr::{
    payload::{CopyOperation, CopyOutcome},
    storage::Storage,
};
use std::io;
#[derive(Clone)]
struct Mem(Vec<u8>);
impl Storage for Mem {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        b.copy_from_slice(&self.0[o as usize..o as usize + b.len()]);
        Ok(())
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> io::Result<usize> {
        let n = b.len().min(3);
        self.0[o as usize..o as usize + n].copy_from_slice(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn overlap_cancel_resume_and_integrity() {
    for (source, destination) in [(0, 7), (7, 0), (0, 40)] {
        let original: Vec<u8> = (0..64).collect();
        let mut disk = Mem(original.clone());
        let mut journal = Mem(vec![0; 320]);
        let op = CopyOperation::prepare(&disk, &mut journal, source, destination, 20, 5).unwrap();
        assert_eq!(
            op.run(&mut disk, &mut journal, |n, _| n < 10).unwrap(),
            CopyOutcome::Cancelled { copied: 10 }
        );
        let op = CopyOperation::load(&journal, 5).unwrap();
        assert_eq!(
            op.run(&mut disk, &mut journal, |_, _| true).unwrap(),
            CopyOutcome::Complete
        );
        assert_eq!(
            &disk.0[destination as usize..destination as usize + 20],
            &original[source as usize..source as usize + 20]
        );
        journal.0[300] ^= 1;
        assert!(CopyOperation::load(&journal, 5).is_err());
    }
}
#[test]
fn changed_storage_is_rejected() {
    let mut disk = Mem((0..64).collect());
    let mut journal = Mem(vec![0; 320]);
    let op = CopyOperation::prepare(&disk, &mut journal, 0, 10, 20, 4).unwrap();
    disk.0[63] ^= 1;
    assert!(op.run(&mut disk, &mut journal, |_, _| true).is_err());
}
struct Failing {
    disk: Mem,
    remaining: usize,
}
impl Storage for Failing {
    fn len(&self) -> io::Result<u64> {
        self.disk.len()
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        self.disk.read_exact_at(o, b)
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("injected write interruption"));
        }
        self.remaining -= 1;
        self.disk.write_at(o, b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.disk.flush()
    }
}
#[test]
fn pending_short_write_resumes_from_snapshot() {
    let original: Vec<u8> = (0..64).collect();
    let mut disk = Failing {
        disk: Mem(original.clone()),
        remaining: 4,
    };
    let mut journal = Mem(vec![0; 320]);
    let op = CopyOperation::prepare(&disk, &mut journal, 0, 4, 32, 8).unwrap();
    assert!(op.run(&mut disk, &mut journal, |_, _| true).is_err());
    disk.remaining = 100;
    CopyOperation::load(&journal, 8)
        .unwrap()
        .run(&mut disk, &mut journal, |_, _| true)
        .unwrap();
    assert_eq!(&disk.disk.0[4..36], &original[..32]);
}
#[test]
fn filesystem_resize_orders_and_stops_on_failure() {
    use partmgr::payload::{FilesystemResize, grow_filesystem, shrink_filesystem};
    use std::{cell::RefCell, rc::Rc};
    struct Fs(Rc<RefCell<Vec<&'static str>>>, bool);
    impl FilesystemResize for Fs {
        fn shrink(&mut self, _: u64) -> io::Result<()> {
            self.0.borrow_mut().push("shrink");
            if self.1 {
                Err(io::Error::other("filesystem failure"))
            } else {
                Ok(())
            }
        }
        fn grow(&mut self, _: u64) -> io::Result<()> {
            self.0.borrow_mut().push("grow");
            Ok(())
        }
    }
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut fs = Fs(log.clone(), false);
    grow_filesystem(&mut fs, 100, || {
        log.borrow_mut().push("boundary");
        Ok(())
    })
    .unwrap();
    assert_eq!(*log.borrow(), vec!["boundary", "grow"]);
    log.borrow_mut().clear();
    shrink_filesystem(&mut fs, 50, || {
        log.borrow_mut().push("boundary");
        Ok(())
    })
    .unwrap();
    assert_eq!(*log.borrow(), vec!["shrink", "boundary"]);
    log.borrow_mut().clear();
    fs.1 = true;
    assert!(
        shrink_filesystem(&mut fs, 20, || {
            log.borrow_mut().push("boundary");
            Ok(())
        })
        .is_err()
    );
    assert_eq!(*log.borrow(), vec!["shrink"]);
}
#[test]
fn every_short_write_boundary_can_resume_in_both_directions() {
    for (source, destination) in [(0, 4), (4, 0)] {
        for boundary in 0..12 {
            let original: Vec<u8> = (0..64).collect();
            let mut disk = Failing {
                disk: Mem(original.clone()),
                remaining: boundary,
            };
            let mut journal = Mem(vec![0; 320]);
            let operation =
                CopyOperation::prepare(&disk, &mut journal, source, destination, 32, 8).unwrap();
            assert!(operation.run(&mut disk, &mut journal, |_, _| true).is_err());
            disk.remaining = 100;
            CopyOperation::load(&journal, 8)
                .unwrap()
                .run(&mut disk, &mut journal, |_, _| true)
                .unwrap();
            assert_eq!(
                &disk.disk.0[destination as usize..destination as usize + 32],
                &original[source as usize..source as usize + 32]
            );
        }
    }
}
#[test]
fn torn_progress_record_recovers_from_previous_pending_record() {
    let original: Vec<u8> = (0..64).collect();
    let mut disk = Mem(original.clone());
    let mut journal = Mem(vec![0; 320]);
    let operation = CopyOperation::prepare(&disk, &mut journal, 0, 4, 16, 8).unwrap();
    operation
        .run(&mut disk, &mut journal, |n, _| n < 8)
        .unwrap();
    // Sequence 2 lives in slot 0; sequence 1 retains the pending first chunk.
    journal.0[96] ^= 1;
    CopyOperation::load(&journal, 8)
        .unwrap()
        .run(&mut disk, &mut journal, |_, _| true)
        .unwrap();
    assert_eq!(&disk.0[4..20], &original[..16]);
}
#[test]
fn layout_commit_requires_verified_payload_completion() {
    let mut disk = Mem((0..64).collect());
    let mut recovery = Mem(vec![0; 320]);
    let op = CopyOperation::prepare(&disk, &mut recovery, 0, 32, 16, 8).unwrap();
    assert!(
        op.commit_layout::<(), _>(&mut disk, &recovery, |_| panic!(
            "must not commit incomplete payload"
        ))
        .is_err()
    );
    op.run(&mut disk, &mut recovery, |_, _| true).unwrap();
    assert_eq!(
        op.commit_layout(&mut disk, &recovery, |_| Ok(42)).unwrap(),
        42
    );
    disk.0[40] ^= 1;
    assert!(
        op.commit_layout::<(), _>(&mut disk, &recovery, |_| panic!(
            "must not commit changed payload"
        ))
        .is_err()
    );
}
#[test]
fn every_torn_journal_write_boundary_can_resume() {
    for boundary in 0..86 {
        let original: Vec<u8> = (0..64).collect();
        let mut disk = Mem(original.clone());
        let mut journal = Failing {
            disk: Mem(vec![0; 320]),
            remaining: 1000,
        };
        let operation = CopyOperation::prepare(&disk, &mut journal, 0, 4, 16, 8).unwrap();
        journal.remaining = boundary;
        assert!(operation.run(&mut disk, &mut journal, |_, _| true).is_err());
        journal.remaining = 1000;
        CopyOperation::load(&journal, 8)
            .unwrap()
            .run(&mut disk, &mut journal, |_, _| true)
            .unwrap();
        assert_eq!(&disk.0[4..20], &original[..16]);
    }
}
struct FlushFailure {
    disk: Mem,
    remaining: usize,
}
impl Storage for FlushFailure {
    fn len(&self) -> io::Result<u64> {
        self.disk.len()
    }
    fn read_exact_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        self.disk.read_exact_at(o, b)
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> io::Result<usize> {
        self.disk.write_at(o, b)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.remaining == 0 {
            return Err(io::Error::other("injected flush failure"));
        }
        self.remaining -= 1;
        Ok(())
    }
}
#[test]
fn disk_and_journal_flush_failures_resume() {
    for boundary in 0..4 {
        let original: Vec<u8> = (0..64).collect();
        let mut disk = FlushFailure {
            disk: Mem(original.clone()),
            remaining: 100,
        };
        let mut journal = FlushFailure {
            disk: Mem(vec![0; 320]),
            remaining: 100,
        };
        let op = CopyOperation::prepare(&disk, &mut journal, 0, 4, 16, 8).unwrap();
        journal.remaining = boundary;
        assert!(op.run(&mut disk, &mut journal, |_, _| true).is_err());
        journal.remaining = 100;
        CopyOperation::load(&journal, 8)
            .unwrap()
            .run(&mut disk, &mut journal, |_, _| true)
            .unwrap();
        assert_eq!(&disk.disk.0[4..20], &original[..16]);
    }
    for boundary in 0..2 {
        let original: Vec<u8> = (0..64).collect();
        let mut disk = FlushFailure {
            disk: Mem(original.clone()),
            remaining: boundary,
        };
        let mut journal = Mem(vec![0; 320]);
        let op = CopyOperation::prepare(&disk, &mut journal, 0, 4, 16, 8).unwrap();
        assert!(op.run(&mut disk, &mut journal, |_, _| true).is_err());
        disk.remaining = 100;
        CopyOperation::load(&journal, 8)
            .unwrap()
            .run(&mut disk, &mut journal, |_, _| true)
            .unwrap();
        assert_eq!(&disk.disk.0[4..20], &original[..16]);
    }
}
#[test]
fn cancellation_after_interruption_finishes_pending_chunk_first() {
    let original: Vec<u8> = (0..64).collect();
    let mut disk = Failing {
        disk: Mem(original.clone()),
        remaining: 1,
    };
    let mut journal = Mem(vec![0; 320]);
    let operation = CopyOperation::prepare(&disk, &mut journal, 0, 4, 16, 8).unwrap();
    assert!(operation.run(&mut disk, &mut journal, |_, _| true).is_err());
    disk.remaining = 100;
    assert_eq!(
        CopyOperation::load(&journal, 8)
            .unwrap()
            .run(&mut disk, &mut journal, |_, _| false)
            .unwrap(),
        CopyOutcome::Cancelled { copied: 8 }
    );
    assert_eq!(&disk.disk.0[4..12], &original[..8]);
    assert_eq!(&disk.disk.0[12..], &original[12..]);
}
#[test]
fn recovered_payload_moves_then_commits_and_inspects_gpt_metadata() {
    use partmgr::{
        codec::{commit_and_inspect, edit_plan, initialize_plan},
        guid::{EFI_SYSTEM_PARTITION, Guid},
        layout::{DiskLayout, Geometry, GptLayout, LbaRange},
        storage::StorageReader,
    };
    let mut disk = Mem(vec![0; 256 * 512]);
    let mut gpt = GptLayout::initialize(
        Geometry::new(256 * 512, 512).unwrap(),
        Guid::from_bytes([1; 16]),
        128,
        128,
    )
    .unwrap();
    gpt.create(
        1,
        EFI_SYSTEM_PARTITION,
        Guid::from_bytes([2; 16]),
        LbaRange::new(40, 60).unwrap(),
    )
    .unwrap();
    let old = DiskLayout::Gpt(gpt.clone());
    let reader = StorageReader::new(&disk).unwrap();
    let plan = initialize_plan(&reader, &old).unwrap();
    plan.commit(&mut disk).unwrap();
    let source: Vec<u8> = (0..20 * 512).map(|n| (n % 251) as u8).collect();
    disk.0[40 * 512..60 * 512].copy_from_slice(&source);
    gpt.set_range(1, LbaRange::new(80, 100).unwrap()).unwrap();
    let plan = edit_plan(&old, &DiskLayout::Gpt(gpt)).unwrap();
    let mut recovery = Mem(vec![0; 256 * 512 + 256]);
    let copy =
        CopyOperation::prepare(&disk, &mut recovery, 40 * 512, 80 * 512, 20 * 512, 4096).unwrap();
    assert_eq!(
        copy.run(&mut disk, &mut recovery, |_, _| false).unwrap(),
        CopyOutcome::Cancelled { copied: 0 }
    );
    assert!(
        copy.commit_layout::<(), _>(&mut disk, &recovery, |_| panic!(
            "incomplete payload must block metadata"
        ))
        .is_err()
    );
    copy.run(&mut disk, &mut recovery, |_, _| true).unwrap();
    let inspected = copy
        .commit_layout(&mut disk, &recovery, |storage| {
            commit_and_inspect(&plan, storage, 512).map_err(io::Error::other)
        })
        .unwrap();
    let DiskLayout::Gpt(gpt) = inspected else {
        panic!("expected GPT")
    };
    assert_eq!(
        gpt.entries()[0].range(),
        Some(LbaRange::new(80, 100).unwrap())
    );
    assert_eq!(&disk.0[80 * 512..100 * 512], &source);
}
