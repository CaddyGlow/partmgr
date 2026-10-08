#![cfg(feature = "std")]

use partmgr::{fs_apfs::*, fs_apfs_audit::*, fs_core::*};
use std::{io, sync::Arc};
use virtdisk::ReadAt;
#[allow(dead_code)]
#[path = "fixtures/apfs_clean.rs"]
mod fixture;
#[path = "fixtures/apfs_queues.rs"]
mod queues;
struct Bytes(Vec<u8>);
impl ReadAt for Bytes {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let at = at as usize;
        out.copy_from_slice(
            self.0
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(128 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn read() -> ApfsReadLimits {
    ApfsReadLimits {
        blocks: 512,
        checkpoint_blocks: 8,
        objects: 256,
        records: 256,
        work: 64 * 1024 * 1024,
    }
}
fn audit() -> ApfsAuditLimits {
    ApfsAuditLimits {
        blocks: 512,
        objects: 512,
        depth: 32,
        work: 64 * 1024 * 1024,
        findings: 64,
    }
}
fn volume(image: Vec<u8>, r: &Resources) -> Result<ApfsVolume> {
    let c = ApfsContainer::open(Arc::new(Bytes(image)), read(), r)?;
    ApfsVolume::open(c, 1026, r)
}
#[test]
fn independent_native_ghost_and_explicit_retirement_lengths_exclude_free() {
    let r = resources();
    let v = volume(queues::queued_seed(), &r).unwrap();
    let report = audit_apfs(&v, audit(), &r).unwrap();
    assert!(report.is_clean(), "{:?}", report.findings());
    assert_eq!(report.allocated_blocks(), 54);
    for block in [200, 202, 203] {
        assert!(report.free_ranges().iter().all(
            |range| block * 4096 < range.offset || block * 4096 >= range.offset + range.length
        ));
    }
    drop(report);
    drop(v);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn malformed_retirement_counts_transactions_domains_duplicates_and_free_bits_reject() {
    for case in 0..9 {
        let r = resources();
        let mut image = queues::queued_seed();
        match case {
            0 => {
                let sm = &mut image[10 * 4096..11 * 4096];
                fixture::p64(sm, 240, 2);
                fixture::seal(sm);
            }
            1 => {
                let sm = &mut image[10 * 4096..11 * 4096];
                fixture::p64(sm, 256, 0);
                fixture::seal(sm);
            }
            2 => image[12 * 4096..13 * 4096]
                .copy_from_slice(&queues::queue(&[(2, 200, 1), (2, 202, 2)], 1029)),
            3 => image[12 * 4096..13 * 4096]
                .copy_from_slice(&queues::queue(&[(1, 41, 1), (1, 202, 2)], 1029)),
            4 => image[12 * 4096..13 * 4096]
                .copy_from_slice(&queues::queue(&[(1, 200, 2), (1, 201, 2)], 1029)),
            5 => image[12 * 4096..13 * 4096]
                .copy_from_slice(&queues::queue(&[(1, 201, 1), (1, 202, 2)], 1029)),
            6 => {
                let b = &mut image[12 * 4096..13 * 4096];
                fixture::p32(b, 4056, 8);
                fixture::seal(b);
            }
            7 => {
                let b = &mut image[12 * 4096..13 * 4096];
                fixture::p16(b, 58, 65534);
                fixture::seal(b);
            }
            _ => {
                let b = &mut image[12 * 4096..13 * 4096];
                let p = 4056 - u16::from_le_bytes(b[62..64].try_into().unwrap()) as usize;
                fixture::p64(b, p, 1);
                fixture::seal(b);
            }
        }
        let result = volume(image, &r).and_then(|v| audit_apfs(&v, audit(), &r));
        assert!(result.is_err(), "case{case} accepted");
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn queued_current_payload_is_conflict_and_caps_cancel_refund() {
    let r = resources();
    let mut image = queues::queued_seed();
    image[12 * 4096..13 * 4096].copy_from_slice(&queues::queue(&[(1, 100, 1), (1, 202, 2)], 1029));
    let v = volume(image, &r).unwrap();
    let report = audit_apfs(&v, audit(), &r).unwrap();
    assert!(!report.is_clean());
    assert!(report.free_ranges().is_empty());
    drop(report);
    drop(v);
    assert_eq!(r.memory.used(), 0);
    let r = resources();
    let v = volume(queues::queued_seed(), &r).unwrap();
    let base = r.memory.used();
    let mut cap = audit();
    cap.work = 1;
    assert_eq!(
        audit_apfs(&v, cap, &r).err().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), base);
    r.cancellation.cancel();
    assert_eq!(
        audit_apfs(&v, audit(), &r).err().unwrap().kind,
        ErrorKind::Cancelled
    );
    drop(v);
    assert_eq!(r.memory.used(), 0);
}
