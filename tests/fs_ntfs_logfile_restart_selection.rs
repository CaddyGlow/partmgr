#![cfg(feature = "std")]
//! Independent restart candidate fixtures, including restored USA trailer bytes.
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ntfs_logfile::{
        NtfsLogFileLimits, NtfsLogRestartOrdering, NtfsLogRestartSelectionReason,
        inspect_logfile_restart_candidate,
    },
    io,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use virtdisk::ReadAt;
const PAGE: usize = 4096;
const LENGTH: usize = 64 * PAGE;
fn w(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn d(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn q(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn protect(b: &mut [u8], usa: usize, marker: u16) {
    w(b, usa, marker);
    for sector in 1..=8 {
        let at = sector * 512 - 2;
        let prior = u16::from_le_bytes([b[at], b[at + 1]]);
        w(b, usa + sector * 2, prior);
        w(b, at, marker);
    }
}
fn restart(version: u16, current: u64, marker: u16) -> Vec<u8> {
    let mut b = vec![0; PAGE];
    b[..4].copy_from_slice(b"RSTR");
    w(&mut b, 4, 32);
    w(&mut b, 6, 9);
    d(&mut b, 16, PAGE as u32);
    d(&mut b, 20, PAGE as u32);
    w(&mut b, 24, 56);
    w(&mut b, 26, if version == 1 { 1 } else { 0 });
    w(&mut b, 28, version);
    q(&mut b, 56, current);
    w(&mut b, 64, 1);
    w(&mut b, 66, u16::MAX);
    w(&mut b, 68, 0);
    d(&mut b, 72, 48);
    w(&mut b, 76, 224);
    w(&mut b, 78, 64);
    q(&mut b, 80, LENGTH as u64);
    w(&mut b, 92, 48);
    w(&mut b, 94, 64);
    w(&mut b, 136, u16::MAX);
    w(&mut b, 138, u16::MAX);
    w(&mut b, 140, 9);
    d(&mut b, 148, 8);
    b[152..160].copy_from_slice(b"N\0T\0F\0S\0");
    protect(&mut b, 32, marker);
    b
}
fn edit(raw: &mut [u8], marker: u16, change: impl FnOnce(&mut [u8])) {
    let usa = u16::from_le_bytes([raw[4], raw[5]]) as usize;
    for sector in 1..=8 {
        let restored = [raw[usa + 2 * sector], raw[usa + 2 * sector + 1]];
        raw[sector * 512 - 2..sector * 512].copy_from_slice(&restored);
    }
    change(raw);
    protect(raw, usa, marker);
}
fn pair(version: u16, a: u64, b: u64) -> Vec<u8> {
    let mut bytes = vec![0; LENGTH];
    bytes[..PAGE].copy_from_slice(&restart(version, a, 0xa001));
    bytes[PAGE..2 * PAGE].copy_from_slice(&restart(version, b, 0xa002));
    bytes
}
struct Image {
    bytes: Vec<u8>,
    length: AtomicU64,
    reads: AtomicU64,
    fail: u64,
    stale: u64,
    cancel_at: u64,
    cancel: Cancellation,
}
impl Image {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            length: AtomicU64::new(bytes.len() as u64),
            bytes,
            reads: AtomicU64::new(0),
            fail: u64::MAX,
            stale: u64::MAX,
            cancel_at: u64::MAX,
            cancel: Cancellation::default(),
        }
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.length.load(Ordering::SeqCst)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if offset == self.fail {
            out[0] = 0x73;
            return Err(io::Error::other("independent restart backend failure"));
        }
        let at = offset as usize;
        out.copy_from_slice(
            self.bytes
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        if offset == self.stale {
            self.length.fetch_sub(1, Ordering::SeqCst);
        }
        if offset == self.cancel_at {
            self.cancel.cancel();
        }
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    }
}
fn limits() -> NtfsLogFileLimits {
    NtfsLogFileLimits {
        restart_page_bytes: PAGE,
        clients: 1,
        work: 10000,
    }
}
const ORDER: NtfsLogRestartOrdering = NtfsLogRestartOrdering::NumericWithoutRollover;
#[test]
fn numeric_candidate_ranks_both_versions_in_both_directions_without_authority() {
    for version in [1, 2] {
        for (a, b, index) in [(100, 200, 1), (200, 100, 0), (0x7ffff, 0x80000, 1)] {
            let r = resources();
            let source = Arc::new(Image::new(pair(version, a, b)));
            let report =
                inspect_logfile_restart_candidate(source.clone(), limits(), ORDER, &r).unwrap();
            assert_eq!(report.selected_index(), Some(index));
            assert_eq!(report.selected_context().unwrap().current_lsn, a.max(b));
            assert_eq!(
                report.reason(),
                Some(NtfsLogRestartSelectionReason::GreaterCurrentLsn)
            );
            assert_eq!(report.ordering(), ORDER);
            assert_eq!(source.reads.load(Ordering::SeqCst), 2);
            assert!(!report.active_window_complete());
            assert!(!report.recovery_complete());
            drop(report);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn equal_full_fixed_up_areas_ignore_usa_markers_and_outside_padding() {
    for version in [1, 2] {
        let mut bytes = pair(version, 100, 100);
        for (offset, marker) in [(0, 0xab01), (PAGE, 0xcd02)] {
            edit(&mut bytes[offset..offset + PAGE], marker, |page| {
                w(page, 76, 520);
                page[280..576].fill(0x59);
            });
        }
        bytes[900] = 0x63;
        bytes[PAGE + 900] = 0x91;
        let r = resources();
        let report =
            inspect_logfile_restart_candidate(Arc::new(Image::new(bytes)), limits(), ORDER, &r)
                .unwrap();
        assert_eq!(report.selected_index(), Some(0));
        assert_eq!(
            report.reason(),
            Some(NtfsLogRestartSelectionReason::EquivalentCopies)
        );
        assert_ne!(
            report.restart().copies()[0].raw()[510],
            report.restart().copies()[1].raw()[510]
        );
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn equal_lsn_conflicts_include_omitted_length_client_tail_and_restored_trailer() {
    for conflict in 0..3 {
        let mut bytes = pair(2, 100, 100);
        for offset in [0, PAGE] {
            edit(&mut bytes[offset..offset + PAGE], 0xab01, |page| {
                w(page, 76, 520)
            });
        }
        edit(&mut bytes[PAGE..2 * PAGE], 0xab01, |page| match conflict {
            0 => d(page, 88, 17),
            1 => page[200] = 0x79,
            _ => page[510] = 0x39,
        });
        let r = resources();
        let report =
            inspect_logfile_restart_candidate(Arc::new(Image::new(bytes)), limits(), ORDER, &r)
                .unwrap();
        assert!(
            report
                .restart()
                .copies()
                .iter()
                .all(|copy| copy.area().is_ok())
        );
        assert_eq!(report.selected_index(), None);
        assert_eq!(report.reason(), None);
        assert_eq!(
            report.stopping_error().unwrap().kind,
            ErrorKind::InvalidData
        );
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn geometry_list_and_client_identity_mismatches_block_numeric_ranking() {
    for mismatch in 0..5 {
        let mut bytes = pair(1, 100, 200);
        edit(&mut bytes[PAGE..2 * PAGE], 0xcd02, |page| match mismatch {
            0 => {
                w(page, 28, 2);
                w(page, 26, 0);
            }
            1 => w(page, 94, 72),
            2 => w(page, 140, 10),
            3 => {
                w(page, 66, 0);
                w(page, 68, u16::MAX);
            }
            _ => page[200] = 0x43,
        });
        let r = resources();
        let report =
            inspect_logfile_restart_candidate(Arc::new(Image::new(bytes)), limits(), ORDER, &r)
                .unwrap();
        assert!(
            report
                .restart()
                .copies()
                .iter()
                .all(|copy| copy.area().is_ok())
        );
        assert_eq!(report.selected_index(), None);
        assert_eq!(
            report.stopping_error().unwrap().kind,
            ErrorKind::Unsupported
        );
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn divergent_context_observations_do_not_prevent_compatible_candidate_ranking() {
    let mut bytes = pair(2, 100, 200);
    edit(&mut bytes[PAGE..2 * PAGE], 0xcd02, |page| {
        q(page, 120, 70);
        q(page, 128, 80);
        d(page, 96, 45);
        w(page, 70, 2);
    });
    let r = resources();
    let report =
        inspect_logfile_restart_candidate(Arc::new(Image::new(bytes)), limits(), ORDER, &r)
            .unwrap();
    assert!(report.restart().copies_disagree());
    assert_eq!(report.selected_index(), Some(1));
    assert_eq!(
        report.selected_context().unwrap().client_oldest_lsn,
        Some(70)
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn complete_format_failures_allow_fallback_with_original_rejected_evidence() {
    for bad_copy in [0, 1] {
        for unsupported in [false, true] {
            let mut bytes = pair(1, 100, 200);
            let offset = bad_copy * PAGE;
            if unsupported {
                edit(&mut bytes[offset..offset + PAGE], 0x7312, |page| {
                    w(page, 28, 3)
                });
            } else {
                bytes[offset + 510] ^= 1;
            }
            let r = resources();
            let report =
                inspect_logfile_restart_candidate(Arc::new(Image::new(bytes)), limits(), ORDER, &r)
                    .unwrap();
            assert_eq!(report.selected_index(), Some((1 - bad_copy) as u8));
            assert_eq!(
                report.reason(),
                Some(NtfsLogRestartSelectionReason::SoleValidCopy)
            );
            let rejected = &report.restart().copies()[bad_copy];
            assert!(rejected.read_complete());
            assert_eq!(
                rejected.area().unwrap_err().kind,
                if unsupported {
                    ErrorKind::Unsupported
                } else {
                    ErrorKind::InvalidData
                }
            );
            assert!(report.stopping_error().is_none());
            drop(report);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn backend_cancellation_and_stale_failures_never_enable_fallback() {
    for mode in 0..3 {
        let r = resources();
        let mut source = Image::new(pair(2, 100, 200));
        match mode {
            0 => source.fail = PAGE as u64,
            1 => {
                source.cancel_at = 0;
                source.cancel = r.cancellation.clone();
            }
            _ => source.stale = PAGE as u64,
        }
        let report =
            inspect_logfile_restart_candidate(Arc::new(source), limits(), ORDER, &r).unwrap();
        assert_eq!(report.selected_index(), None);
        assert!(report.selected_context().is_none());
        assert!(report.reason().is_none());
        let error = report.stopping_error().unwrap();
        assert_eq!(
            error.kind,
            match mode {
                0 => ErrorKind::Io,
                1 => ErrorKind::Cancelled,
                _ => ErrorKind::StalePlan,
            }
        );
        if mode == 0 {
            assert!(error.source.is_some());
            assert!(!report.restart().copies()[1].read_complete());
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn comparison_work_and_copy_resource_failures_block_selection_and_refund() {
    let r = resources();
    let source = Arc::new(Image::new(pair(1, 100, 100)));
    let report = inspect_logfile_restart_candidate(source, limits(), ORDER, &r).unwrap();
    let work = report.work();
    let restart_work = report.restart().work();
    assert!(work > restart_work);
    drop(report);
    assert_eq!(r.memory.used(), 0);
    for maximum in [0, restart_work, work - 1] {
        let mut cap = limits();
        cap.work = maximum;
        match inspect_logfile_restart_candidate(
            Arc::new(Image::new(pair(1, 100, 100))),
            cap,
            ORDER,
            &r,
        ) {
            Ok(report) => {
                assert_eq!(report.selected_index(), None);
                assert_eq!(
                    report.stopping_error().unwrap().kind,
                    ErrorKind::BudgetExhausted
                );
                assert!(report.work() <= maximum);
            }
            Err(error) => assert_eq!(error.kind, ErrorKind::BudgetExhausted),
        }
        assert_eq!(r.memory.used(), 0);
    }
    let tiny = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert!(
        inspect_logfile_restart_candidate(
            Arc::new(Image::new(pair(1, 100, 100))),
            limits(),
            ORDER,
            &tiny
        )
        .is_err()
    );
    assert_eq!(tiny.memory.used(), 0);
}

#[test]
fn one_valid_copy_cannot_hide_rejected_client_resource_limit_or_two_bad_formats() {
    for resources_bad in [true, false] {
        let mut bytes = pair(1, 100, 200);
        if resources_bad {
            edit(&mut bytes[PAGE..2 * PAGE], 0xcd02, |page| w(page, 64, 2));
        } else {
            bytes[510] ^= 1;
            bytes[PAGE + 510] ^= 1;
        }
        let r = resources();
        let report =
            inspect_logfile_restart_candidate(Arc::new(Image::new(bytes)), limits(), ORDER, &r)
                .unwrap();
        assert_eq!(report.selected_index(), None);
        assert_eq!(
            report.stopping_error().unwrap().kind,
            if resources_bad {
                ErrorKind::BudgetExhausted
            } else {
                ErrorKind::InvalidData
            }
        );
        if resources_bad {
            assert!(report.restart().copies()[0].area().is_ok());
            assert!(report.restart().copies()[1].read_complete());
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
