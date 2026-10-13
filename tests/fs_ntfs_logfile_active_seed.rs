#![cfg(feature = "std")]
//! Raw independent restart-only discovery arithmetic fixtures; no native claim.
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ntfs_logfile::*,
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
    cancel_final_len: bool,
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
            cancel_final_len: false,
            cancel: Cancellation::default(),
        }
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        if self.cancel_final_len && self.reads.load(Ordering::SeqCst) >= 2 {
            self.cancel.cancel();
        }
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

fn seed_limits() -> NtfsLogDiscoverySeedLimits {
    NtfsLogDiscoverySeedLimits {
        restart: limits(),
        pages: 65,
        work: 20000,
    }
}
fn lsn(offset: usize) -> u64 {
    (9u64 << 16) | (offset as u64 / 8)
}
fn input(version: u16, offset: usize, payload: u32, oldest: u64) -> Vec<u8> {
    let current = lsn(offset);
    let mut raw = pair(version, current, current);
    for copy in raw[..2 * PAGE].chunks_mut(PAGE) {
        edit(copy, 0xb001, |page| {
            d(page, 56 + 32, payload);
            q(page, 56 + 64, oldest);
        });
    }
    // Every ordinary byte deliberately invalid, demonstrating restart-only I/O.
    raw[2 * PAGE..].fill(0x91);
    raw
}
#[test]
fn declared_endpoint_is_restart_only_for_both_versions_and_wrap_edges() {
    for version in [1, 2] {
        let first = if version == 1 { 4 * PAGE } else { 34 * PAGE };
        for (offset, payload, end, wraps, pages) in [
            (first + 64, 0, first + 111, 0, 1),
            (first + 64, 1, first + 112, 0, 1),
            (first + PAGE - 48, 0, first + PAGE - 1, 0, 1),
            (first + PAGE - 48, 1, first + PAGE + 64, 0, 2),
            (LENGTH - PAGE + 64, 4032, first + 111, 1, 2),
            (LENGTH - PAGE + 64, 3984, LENGTH - 1, 0, 1),
        ] {
            let r = resources();
            let image = Arc::new(Image::new(input(version, offset, payload, 0)));
            let report =
                inspect_logfile_discovery_seed(image.clone(), seed_limits(), ORDER, &r).unwrap();
            let seed = report.seed().expect("declared seed");
            assert_eq!(seed.ordinary_start(), first as u64);
            let span = seed.declared_endpoint().unwrap();
            assert_eq!(
                (
                    span.final_byte_offset(),
                    span.physical_wraps(),
                    span.pages()
                ),
                (end as u64, wraps, pages)
            );
            assert_eq!(image.reads.load(Ordering::SeqCst), 2);
            assert!(!report.active_window_complete());
            assert!(!report.recovery_complete());
            assert_eq!(
                report.require_active_window().unwrap_err().kind,
                ErrorKind::Unsupported
            );
            drop(report);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn near_full_ring_revisits_first_page_without_overlapping_header() {
    for version in [1, 2] {
        let first = if version == 1 { 4 * PAGE } else { 34 * PAGE };
        let count = (LENGTH - first) / PAGE;
        let total = count * (PAGE - 64) - 8;
        let r = resources();
        let image = Arc::new(Image::new(input(
            version,
            first + 128,
            (total - 48) as u32,
            0,
        )));
        let report =
            inspect_logfile_discovery_seed(image.clone(), seed_limits(), ORDER, &r).unwrap();
        let span = report.seed().unwrap().declared_endpoint().unwrap();
        assert_eq!(span.pages(), count + 1);
        assert_eq!(span.physical_wraps(), 1);
        assert_eq!(span.final_byte_offset(), (first + 119) as u64);
        assert_eq!(image.reads.load(Ordering::SeqCst), 2);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn pseudo_zero_oldest_selection_and_no_ordinary_record_reads() {
    for version in [1, 2] {
        let first = if version == 1 { 4 * PAGE } else { 34 * PAGE };
        for current in [0, lsn(64), lsn(first + 64)] {
            let r = resources();
            let mut bytes = pair(version, current, current);
            for copy in bytes[..2 * PAGE].chunks_mut(PAGE) {
                edit(copy, 0xc001, |page| q(page, 120, lsn(64)));
            }
            let image = Arc::new(Image::new(bytes));
            let report =
                inspect_logfile_discovery_seed(image.clone(), seed_limits(), ORDER, &r).unwrap();
            let seed = report.seed().unwrap();
            if current == 0 {
                assert_eq!(seed.current_address(), NtfsLogSeedAddress::Zero);
                assert_eq!(seed.numeric_oldest_lsn(), 0);
            } else if current == lsn(64) {
                assert!(matches!(
                    seed.current_address(),
                    NtfsLogSeedAddress::Pseudo { .. }
                ));
                assert!(seed.declared_endpoint().is_none());
            } else {
                assert_eq!(seed.numeric_oldest_lsn(), lsn(64));
                assert!(matches!(
                    seed.oldest_address(),
                    NtfsLogSeedAddress::Pseudo { .. }
                ));
            }
            assert_eq!(image.reads.load(Ordering::SeqCst), 2);
            drop(report);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn selected_copy_owns_declared_length_and_original_rejected_diagnostics() {
    let r = resources();
    let mut bytes = input(2, 34 * PAGE + 64, 73, 0);
    edit(&mut bytes[PAGE..2 * PAGE], 0xd001, |page| {
        q(page, 56, lsn(35 * PAGE + 64));
        d(page, 88, 91);
    });
    let image = Arc::new(Image::new(bytes));
    let report = inspect_logfile_discovery_seed(image, seed_limits(), ORDER, &r).unwrap();
    assert_eq!(report.selection().selected_index(), Some(1));
    assert_eq!(
        report
            .selection()
            .selected_context()
            .unwrap()
            .last_lsn_data_bytes,
        91
    );
    assert_eq!(
        report
            .seed()
            .unwrap()
            .declared_endpoint()
            .unwrap()
            .final_byte_offset(),
        (35 * PAGE + 64 + 48 + 91 - 1) as u64
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
    let mut bytes = input(1, 4 * PAGE + 64, 0, 0);
    bytes[510] ^= 1;
    let report =
        inspect_logfile_discovery_seed(Arc::new(Image::new(bytes)), seed_limits(), ORDER, &r)
            .unwrap();
    assert_eq!(report.selection().selected_index(), Some(1));
    assert!(report.selection().restart().copies()[0].area().is_err());
    assert!(report.seed().is_some());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn invalid_address_span_pages_and_aggregate_work_refuse_without_extra_io() {
    for kind in 0..5 {
        let r = resources();
        let mut lim = seed_limits();
        let first = 34 * PAGE;
        let (offset, payload) = match kind {
            0 => (first + 8, 0),
            1 => (LENGTH, 0),
            2 => (first + 64, u32::MAX),
            3 => {
                lim.pages = 1;
                (first + PAGE - 48, 1)
            }
            _ => {
                lim.work = 0;
                (first + 64, 0)
            }
        };
        let image = Arc::new(Image::new(input(2, offset, payload, 0)));
        let report = inspect_logfile_discovery_seed(image.clone(), lim, ORDER, &r).unwrap();
        assert!(report.seed().is_none());
        assert!(report.stopping_error().is_some());
        assert!(image.reads.load(Ordering::SeqCst) <= 2);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn source_cancel_backend_and_length_failures_withhold_seed_and_keep_causes() {
    for kind in 0..3 {
        let r = resources();
        let mut image = Image::new(input(2, 34 * PAGE + 64, 0, 0));
        match kind {
            0 => image.fail = PAGE as u64,
            1 => image.stale = PAGE as u64,
            _ => {
                image.cancel_at = PAGE as u64;
                image.cancel = r.cancellation.clone()
            }
        }
        let report =
            inspect_logfile_discovery_seed(Arc::new(image), seed_limits(), ORDER, &r).unwrap();
        assert!(report.seed().is_none());
        let error = report.stopping_error().unwrap();
        if kind == 0 {
            assert!(format!("{error:?}").contains("independent restart backend failure"));
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn preflight_memory_refusal_allocates_no_source_pages() {
    let r = Resources {
        memory: Budget::new(2 * PAGE as u64 + 2047),
        cancellation: Cancellation::default(),
    };
    let image = Arc::new(Image::new(input(1, 4 * PAGE + 64, 0, 0)));
    assert!(
        matches!(inspect_logfile_discovery_seed(image.clone(),seed_limits(),ORDER,&r),Err(error) if error.kind==ErrorKind::BudgetExhausted)
    );
    assert_eq!(image.reads.load(Ordering::SeqCst), 0);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn final_length_callback_cancellation_withholds_seed() {
    let r = resources();
    let mut image = Image::new(input(2, 34 * PAGE + 64, 0, 0));
    image.cancel_final_len = true;
    image.cancel = r.cancellation.clone();
    let report = inspect_logfile_discovery_seed(Arc::new(image), seed_limits(), ORDER, &r).unwrap();
    assert!(report.seed().is_none());
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::Cancelled);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn relocated_restart_fields_crossing_usa_fail_closed() {
    // File-size at area+24 crosses sector trailer510 with area480.
    // The admitted client-offset bound excludes this layout; do not decode raw USA bytes.
    let r = resources();
    let mut bytes = input(2, 34 * PAGE + 64, 91, 0);
    for copy in bytes[..2 * PAGE].chunks_mut(PAGE) {
        edit(copy, 0xe001, |page| {
            page.copy_within(56..280, 480);
            w(page, 24, 480);
        });
    }
    let report =
        inspect_logfile_discovery_seed(Arc::new(Image::new(bytes)), seed_limits(), ORDER, &r)
            .unwrap();
    assert!(report.seed().is_none());
    assert!(report.selection().selected_context().is_none());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
