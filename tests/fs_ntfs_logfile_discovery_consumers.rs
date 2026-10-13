#![cfg(feature = "std")]
//! Independently framed synthetic native discovery consumers; no Windows evidence.
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
    reads: AtomicU64,
    by_offset: std::sync::Mutex<std::collections::BTreeMap<u64, u64>>,
    drift: Option<(u64, u64)>,
    fail_once: Option<(u64, u64)>,
    cancel_at: Option<(u64, u64)>,
    cancel: Cancellation,
}
impl Image {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            reads: AtomicU64::new(0),
            by_offset: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            drift: None,
            fail_once: None,
            cancel_at: None,
            cancel: Cancellation::default(),
        }
    }
    fn count(&self, offset: u64) -> u64 {
        *self.by_offset.lock().unwrap().get(&offset).unwrap_or(&0)
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let ordinal = {
            let mut counts = self.by_offset.lock().unwrap();
            let n = counts.entry(offset).or_default();
            *n += 1;
            *n
        };
        if self.fail_once == Some((offset, ordinal)) {
            return Err(io::Error::other("independent transient probe failure"));
        }
        let at = offset as usize;
        out.copy_from_slice(
            self.bytes
                .get(at..at + out.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        if self
            .drift
            .is_some_and(|(where_, when)| where_ == offset && ordinal >= when)
        {
            out[100] ^= 1;
        }
        if self.cancel_at == Some((offset, ordinal)) {
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
fn tail_limits() -> NtfsLogTailDiscoveryLimits {
    NtfsLogTailDiscoveryLimits {
        seed: seed_limits(),
        candidates: 32,
        retained_bytes: 256 << 10,
        work: 1 << 20,
    }
}
fn ordinary_limits() -> NtfsLogOrdinaryDiscoveryLimits {
    NtfsLogOrdinaryDiscoveryLimits {
        tail: tail_limits(),
        pages: 12,
        retained_bytes: 256 << 10,
        work: 2 << 20,
    }
}
fn framed(
    version: u16,
    ordinary: bool,
    target: usize,
    record: u64,
    count: u16,
    position: u16,
) -> Vec<u8> {
    let mut page = vec![0; PAGE];
    page[..4].copy_from_slice(b"RCRD");
    w(&mut page, 4, 40);
    w(&mut page, 6, 9);
    q(
        &mut page,
        8,
        if version == 1 && !ordinary {
            target as u64
        } else {
            record
        },
    );
    d(&mut page, 16, 1);
    w(&mut page, 20, count);
    w(&mut page, 22, position);
    w(&mut page, 24, 112);
    q(&mut page, 32, record);
    if version == 2 && !ordinary {
        d(&mut page, 60, target as u32);
    }
    // Independently encode an empty48-byte LFS record after the native page header.
    q(&mut page, 64, record);
    d(&mut page, 88, 0);
    w(&mut page, 92, 9);
    w(&mut page, 94, 0);
    d(&mut page, 96, 1);
    protect(&mut page, 40, 0xd00d);
    page
}
fn install(raw: &mut [u8], page: usize, bytes: &[u8]) {
    raw[page * PAGE..(page + 1) * PAGE].copy_from_slice(bytes);
}
fn fixture(version: u16, start: usize) -> Vec<u8> {
    let mut raw = input(version, start * PAGE + 64, 0, 0);
    raw[2 * PAGE..].fill(0);
    install(
        &mut raw,
        2,
        &framed(version, false, start * PAGE, lsn(start * PAGE + 64), 1, 1),
    );
    for index in if version == 1 { 4..64 } else { 34..64 } {
        let record = (8u64 << 16) | ((index * PAGE + 64) as u64 / 8);
        install(
            &mut raw,
            index,
            &framed(version, true, index * PAGE, record, 1, 1),
        );
    }
    install(
        &mut raw,
        start,
        &framed(version, true, start * PAGE, lsn(start * PAGE + 64), 1, 1),
    );
    raw
}
#[test]
fn actual_tail_consumers_keep_native_slots_and_rejected_mates_for_both_versions() {
    for version in [1, 2] {
        let first = if version == 1 { 4 } else { 34 };
        let r = resources();
        let image = Arc::new(Image::new(fixture(version, first)));
        let before = r.memory.used();
        let report =
            inspect_logfile_tail_discovery(image.clone(), tail_limits(), ORDER, &r).unwrap();
        assert!(report.stopping_error().is_none());
        assert_eq!(report.candidate_chain(), &[1]);
        let chosen = &report.candidates()[1];
        assert_eq!(chosen.source_offset(), 8192);
        assert_eq!(chosen.target_offset(), Some((first * PAGE) as u64));
        assert_eq!(&chosen.raw()[..4], b"RCRD");
        assert!(report.candidates()[0].error().is_some());
        assert!(image.count(8192) >= 2);
        assert!(!report.active_window_complete());
        assert!(!report.recovery_complete());
        assert!(report.require_active_window().is_err());
        assert!(r.memory.used() > before);
        drop(report);
        assert_eq!(r.memory.used(), before);
    }
}
#[test]
fn actual_ordinary_consumers_follow_pages_and_observe_a_bounded_boundary() {
    for version in [1, 2] {
        let first = if version == 1 { 4 } else { 34 };
        let r = resources();
        let image = Arc::new(Image::new(fixture(version, first)));
        let before = r.memory.used();
        let report =
            inspect_logfile_ordinary_discovery(image.clone(), ordinary_limits(), ORDER, &r)
                .unwrap();
        assert!(
            report.stopping_error().is_none(),
            "{:?}",
            report.stopping_error()
        );
        assert_eq!(report.stop(), NtfsLogOrdinaryStop::BoundaryObserved);
        assert_eq!(
            report
                .pages()
                .iter()
                .map(|p| p.offset())
                .collect::<Vec<_>>(),
            vec![
                (first * PAGE) as u64,
                ((first + 1) * PAGE) as u64,
                ((first + 2) * PAGE) as u64
            ]
        );
        let end = report.endpoint().unwrap();
        assert_eq!(end.last_lsn, lsn(first * PAGE + 64));
        assert_eq!(end.next_page, (first * PAGE) as u64);
        assert!(end.reuse);
        assert!(!report.active_window_complete());
        assert!(!report.recovery_complete());
        assert!(image.count((first * PAGE) as u64) >= 2);
        drop(report);
        assert_eq!(r.memory.used(), before);
    }
}
#[test]
fn exact_repeated_candidate_restart_and_ordinary_guards_suppress_observations() {
    for (offset, ordinal, ordinary) in [(0, 2, false), (8192, 2, false), (4 * PAGE as u64, 2, true)]
    {
        let r = resources();
        let mut image = Image::new(fixture(1, 4));
        image.drift = Some((offset, ordinal));
        let image = Arc::new(image);
        if ordinary {
            let report =
                inspect_logfile_ordinary_discovery(image, ordinary_limits(), ORDER, &r).unwrap();
            assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::StalePlan);
            assert!(report.endpoint().is_none());
        } else {
            let report = inspect_logfile_tail_discovery(image, tail_limits(), ORDER, &r).unwrap();
            assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::StalePlan);
            assert!(report.candidate_chain().is_empty());
        }
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn transient_boundary_probe_io_is_not_hidden_by_a_successful_final_guard() {
    let r = resources();
    let mut image = Image::new(fixture(1, 4));
    image.fail_once = Some((6 * PAGE as u64, 1));
    let image = Arc::new(image);
    let report =
        inspect_logfile_ordinary_discovery(image.clone(), ordinary_limits(), ORDER, &r).unwrap();
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::Io);
    assert!(report.endpoint().is_none());
    assert!(image.count(6 * PAGE as u64) >= 2);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn ordinary_cancellation_work_and_memory_fail_closed_and_refund() {
    let r = resources();
    let mut image = Image::new(fixture(1, 4));
    image.cancel = r.cancellation.clone();
    image.cancel_at = Some((4 * PAGE as u64, 1));
    let report =
        inspect_logfile_ordinary_discovery(Arc::new(image), ordinary_limits(), ORDER, &r).unwrap();
    assert!(report.stopping_error().is_some());
    assert!(report.endpoint().is_none());
    drop(report);
    assert_eq!(r.memory.used(), 0);
    let r = resources();
    let mut limits = ordinary_limits();
    limits.work = 20000;
    match inspect_logfile_ordinary_discovery(Arc::new(Image::new(fixture(1, 4))), limits, ORDER, &r)
    {
        Ok(report) => {
            assert!(report.stopping_error().is_some());
            assert!(report.endpoint().is_none());
        }
        Err(e) => assert_eq!(e.kind, ErrorKind::BudgetExhausted),
    };
    assert_eq!(r.memory.used(), 0);
    let r = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert!(
        inspect_logfile_ordinary_discovery(
            Arc::new(Image::new(fixture(1, 4))),
            ordinary_limits(),
            ORDER,
            &r
        )
        .is_err()
    );
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn early_fast_nonstarting_fragment_does_not_hide_later_starting_pair() {
    let r = resources();
    let mut raw = fixture(2, 34);
    install(
        &mut raw,
        2,
        &framed(2, false, 34 * PAGE, lsn(34 * PAGE + 64), 3, 2),
    );
    install(
        &mut raw,
        3,
        &framed(2, false, 35 * PAGE, lsn(35 * PAGE + 64), 1, 1),
    );
    let report =
        inspect_logfile_tail_discovery(Arc::new(Image::new(raw)), tail_limits(), ORDER, &r)
            .unwrap();
    assert!(report.stopping_error().is_none());
    assert_eq!(report.candidate_chain(), &[3]);
    assert_eq!(report.candidates()[3].source_offset(), 3 * PAGE as u64);
    assert_eq!(
        report.candidates()[3].target_offset(),
        Some(35 * PAGE as u64)
    );
}

#[test]
fn actual_multipage_declared_current_scans_original_start_not_endpoint_page() {
    let r = resources();
    let mut raw = fixture(1, 4);
    for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
        edit(restart, 0xe001, |fixed| d(fixed, 88, 4096));
    }
    let report =
        inspect_logfile_ordinary_discovery(Arc::new(Image::new(raw)), ordinary_limits(), ORDER, &r)
            .unwrap();
    assert!(report.stopping_error().is_none());
    let declared = report
        .tail_report()
        .seed_report()
        .seed()
        .unwrap()
        .declared_endpoint()
        .unwrap();
    assert_eq!(declared.final_page_offset(), 5 * PAGE as u64);
    assert_eq!(report.pages()[0].offset(), 4 * PAGE as u64);
    assert_eq!(report.endpoint().unwrap().next_page, 4 * PAGE as u64);
    assert!(!report.active_window_complete());
}
#[test]
fn actual_ordinary_wrap_requires_next_encoded_generation() {
    for version in [1, 2] {
        let first = if version == 1 { 4 } else { 34 };
        let r = resources();
        let mut raw = fixture(version, 63);
        let wrapped = (10u64 << 16) | ((first * PAGE + 64) as u64 / 8);
        install(
            &mut raw,
            first,
            &framed(version, true, first * PAGE, wrapped, 1, 1),
        );
        let report = inspect_logfile_ordinary_discovery(
            Arc::new(Image::new(raw)),
            ordinary_limits(),
            ORDER,
            &r,
        )
        .unwrap();
        assert!(report.stopping_error().is_none());
        assert_eq!(report.pages()[0].offset(), 63 * PAGE as u64);
        assert_eq!(report.pages()[1].offset(), first as u64 * PAGE as u64);
        let endpoint = report.endpoint().unwrap();
        assert_eq!(endpoint.generation, 10);
        assert_eq!(endpoint.last_lsn, wrapped);
        assert_eq!(endpoint.next_page, first as u64 * PAGE as u64);
    }
}

#[test]
fn literal_remaining_lookahead_keeps_fixed_address_without_wrap() {
    let r = resources();
    let mut raw = fixture(1, 4);
    install(
        &mut raw,
        4,
        &framed(1, true, 4 * PAGE, lsn(4 * PAGE + 64), 4, 1),
    );
    let image = Arc::new(Image::new(raw));
    let report =
        inspect_logfile_ordinary_discovery(image.clone(), ordinary_limits(), ORDER, &r).unwrap();
    assert!(report.stopping_error().is_none());
    assert_eq!(report.stop(), NtfsLogOrdinaryStop::BoundaryObserved);
    let trace = report.lookahead_trace().unwrap();
    assert_eq!(
        (trace.fixed_current, trace.target),
        (5 * PAGE as u64, 6 * PAGE as u64)
    );
    assert_eq!(
        (trace.count, trace.position, trace.arithmetic_steps),
        (4, 1, 2)
    );
    assert_eq!((trace.initial_generation, trace.final_generation), (9, 9));
    assert!(!trace.matched_first_probe);
    assert_eq!(
        report
            .pages()
            .iter()
            .map(|p| p.offset())
            .collect::<Vec<_>>(),
        vec![4 * PAGE as u64, 5 * PAGE as u64, 6 * PAGE as u64]
    );
    assert_eq!(image.count(7 * PAGE as u64), 0);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn literal_remaining_lookahead_counts_repeated_wraps_at_same_target() {
    let r = resources();
    let mut raw = fixture(1, 62);
    install(
        &mut raw,
        62,
        &framed(1, true, 62 * PAGE, lsn(62 * PAGE + 64), 4, 1),
    );
    let report =
        inspect_logfile_ordinary_discovery(Arc::new(Image::new(raw)), ordinary_limits(), ORDER, &r)
            .unwrap();
    assert!(report.stopping_error().is_none());
    assert_eq!(report.stop(), NtfsLogOrdinaryStop::BoundaryObserved);
    let trace = report.lookahead_trace().unwrap();
    assert_eq!(
        (trace.fixed_current, trace.target),
        (63 * PAGE as u64, 4 * PAGE as u64)
    );
    assert_eq!(trace.arithmetic_steps, 2);
    assert_eq!((trace.initial_generation, trace.final_generation), (10, 12));
    assert_eq!(report.pages().last().unwrap().offset(), 4 * PAGE as u64);
    assert!(!report.active_window_complete());
}
#[test]
fn matching_first_probe_is_really_reread_at_same_address_and_conflicts() {
    let r = resources();
    let mut raw = fixture(1, 4);
    install(
        &mut raw,
        6,
        &framed(1, true, 6 * PAGE, lsn(6 * PAGE + 64), 4, 2),
    );
    let image = Arc::new(Image::new(raw));
    let report =
        inspect_logfile_ordinary_discovery(image.clone(), ordinary_limits(), ORDER, &r).unwrap();
    assert_eq!(
        report.stop(),
        NtfsLogOrdinaryStop::SubsequentGenerationConflict
    );
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::InvalidData
    );
    assert!(report.endpoint().is_none());
    let trace = report.lookahead_trace().unwrap();
    assert!(trace.matched_first_probe);
    assert_eq!(
        (trace.count, trace.position, trace.arithmetic_steps),
        (5, 2, 2)
    );
    assert_eq!(trace.target, 6 * PAGE as u64);
    assert_eq!(
        report
            .pages()
            .iter()
            .map(|p| p.offset())
            .collect::<Vec<_>>(),
        vec![
            4 * PAGE as u64,
            5 * PAGE as u64,
            6 * PAGE as u64,
            6 * PAGE as u64
        ]
    );
    assert!(image.count(6 * PAGE as u64) >= 4);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn remaining_loop_is_charged_to_actual_combined_work_ceiling() {
    let mut raw = fixture(1, 4);
    install(
        &mut raw,
        4,
        &framed(1, true, 4 * PAGE, lsn(4 * PAGE + 64), u16::MAX, 1),
    );
    let r = resources();
    let mut limits = ordinary_limits();
    limits.work = 100000;
    let report =
        inspect_logfile_ordinary_discovery(Arc::new(Image::new(raw)), limits, ORDER, &r).unwrap();
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert!(report.endpoint().is_none());
    assert!(report.work() <= limits.work);
    let trace = report
        .lookahead_trace()
        .expect("partial arithmetic evidence retained");
    assert!(trace.arithmetic_steps > 0 && trace.arithmetic_steps < u32::from(u16::MAX) - 2);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_probe_plus_one_uses_u32_count_without_narrowing_u16_maximum() {
    let r = resources();
    let mut raw = fixture(1, 4);
    install(
        &mut raw,
        6,
        &framed(1, true, 6 * PAGE, lsn(6 * PAGE + 64), u16::MAX, 2),
    );
    let report =
        inspect_logfile_ordinary_discovery(Arc::new(Image::new(raw)), ordinary_limits(), ORDER, &r)
            .unwrap();
    assert_eq!(
        report.stop(),
        NtfsLogOrdinaryStop::SubsequentGenerationConflict
    );
    let trace = report.lookahead_trace().unwrap();
    assert_eq!(trace.count, 65536);
    assert_eq!(trace.arithmetic_steps, 65533);
    assert!(report.endpoint().is_none());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn sealed_overlay_uses_native_tail_winner_and_reprotects_without_mutating_source() {
    for version in [1, 2] {
        let first = if version == 1 { 4 } else { 34 };
        let mut raw = fixture(version, first);
        let newer = lsn(first * PAGE + 128);
        install(
            &mut raw,
            2,
            &framed(version, false, first * PAGE, newer, 1, 1),
        );
        let original = raw.clone();
        let image = Arc::new(Image::new(raw));
        let r = resources();
        let before = r.memory.used();
        let view = inspect_logfile_read_only_overlay(
            image.clone(),
            NtfsLogOverlayLimits {
                discovery: ordinary_limits(),
                pages: 32,
                retained_bytes: 512 << 10,
                work: 4 << 20,
            },
            ORDER,
            &r,
        )
        .unwrap();
        assert_eq!(view.pages().len(), 1);
        let replacement = &view.pages()[0];
        assert_eq!(replacement.target(), (first * PAGE) as u64);
        assert_eq!(replacement.source_candidate_index(), 1);
        assert_eq!(
            view.discovery().tail_report().candidates()[1].source_offset(),
            (2 * PAGE) as u64
        );
        assert_eq!(
            replacement.original_target_raw(),
            &original[first * PAGE..(first + 1) * PAGE]
        );
        let page = replacement.normalized_raw();
        assert_eq!(u16::from_le_bytes(page[20..22].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(page[22..24].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(page[40..42].try_into().unwrap()), 1);
        for sector in 1..=8 {
            assert_eq!(&page[sector * 512 - 2..sector * 512], &1u16.to_le_bytes());
        }
        if version == 1 {
            assert_eq!(u64::from_le_bytes(page[8..16].try_into().unwrap()), newer);
        } else {
            assert_eq!(&page[60..64], &[0; 4]);
        }
        let mut crossing = vec![0; PAGE + 16];
        view.read_exact_at((first * PAGE - 8) as u64, &mut crossing)
            .unwrap();
        assert_eq!(&crossing[..8], &original[first * PAGE - 8..first * PAGE]);
        assert_eq!(&crossing[8..8 + PAGE], page);
        assert_eq!(
            &crossing[8 + PAGE..],
            &original[(first + 1) * PAGE..(first + 1) * PAGE + 8]
        );
        assert_eq!(image.bytes, original);
        assert!(!view.active_window_complete());
        assert!(!view.recovery_complete());
        assert!(view.check_source(4 << 20, &r).is_ok());
        assert!(view.check_source(1, &r).is_err());
        drop(view);
        assert_eq!(r.memory.used(), before);
    }
}
#[test]
fn overlay_successor_assembles_exact_record_and_preserves_outside_bound_observation() {
    let image = Arc::new(Image::new(fixture(1, 4)));
    let r = resources();
    let before = r.memory.used();
    let view = Arc::new(
        inspect_logfile_read_only_overlay(
            image,
            NtfsLogOverlayLimits {
                discovery: ordinary_limits(),
                pages: 32,
                retained_bytes: 512 << 10,
                work: 4 << 20,
            },
            ORDER,
            &r,
        )
        .unwrap(),
    );
    let report = inspect_logfile_overlay_successor(
        view,
        limits(),
        NtfsLogRecordLimits {
            pages: 4,
            payload_bytes: 4096,
            work: 1 << 20,
        },
        lsn(4 * PAGE + 64),
        4 << 20,
        &r,
    )
    .unwrap();
    assert!(report.record().complete());
    assert_eq!(
        report.observation(),
        NtfsLogSuccessorObservation::OutsideObservedBounds
    );
    assert!(!report.active_window_complete());
    drop(report);
    assert_eq!(r.memory.used(), before);
}
#[test]
fn later_fast_mismatch_preserves_native_first_chain_replacement_start() {
    let mut raw = fixture(2, 34);
    for (slot, target, position) in [(2, 34, 1), (3, 35, 2), (4, 36, 3)] {
        let h = framed(
            2,
            false,
            target * PAGE,
            lsn(target * PAGE + 64),
            3,
            position,
        );
        install(&mut raw, slot, &h);
    }
    // First ordinary page agrees with its fast copy. The next home is an old
    // generation: native page_off1 still records FIRST chain page, not35P.
    install(
        &mut raw,
        34,
        &framed(2, true, 34 * PAGE, lsn(34 * PAGE + 64), 3, 1),
    );
    let image = Arc::new(Image::new(raw));
    let r = resources();
    let view = inspect_logfile_read_only_overlay(
        image,
        NtfsLogOverlayLimits {
            discovery: ordinary_limits(),
            pages: 32,
            retained_bytes: 512 << 10,
            work: 4 << 20,
        },
        ORDER,
        &r,
    )
    .unwrap();
    assert_eq!(
        view.pages().iter().map(|p| p.target()).collect::<Vec<_>>(),
        vec![34 * PAGE as u64, 35 * PAGE as u64, 36 * PAGE as u64]
    );
    assert_eq!(
        view.pages()
            .iter()
            .map(|p| p.source_candidate_index())
            .collect::<Vec<_>>(),
        vec![1, 3, 5]
    );
    for page in view.pages() {
        assert_eq!(&page.normalized_raw()[20..24], &[1, 0, 1, 0]);
    }
}

#[test]
fn partial_trace_retains_full_planned_remainder_and_zero_winner_residual() {
    let r = resources();
    let mut raw = fixture(1, 4);
    install(
        &mut raw,
        4,
        &framed(1, true, 4 * PAGE, lsn(4 * PAGE + 64), 4, 1),
    );
    let source = Arc::new(Image::new(raw.clone()));
    let view = inspect_logfile_read_only_overlay(
        source,
        NtfsLogOverlayLimits {
            discovery: ordinary_limits(),
            pages: 32,
            retained_bytes: 512 << 10,
            work: 4 << 20,
        },
        ORDER,
        &r,
    )
    .unwrap();
    let partial = view.discovery().partial_transfer().unwrap();
    assert_eq!(
        (
            partial.original_start(),
            partial.planned_remaining(),
            partial.pre_overlay_count()
        ),
        (6 * PAGE as u64, 2, 2)
    );
    assert!(partial.complete_native_branch());
    assert!(view.pages().is_empty());
    assert_eq!(
        (
            view.partial_residual().start(),
            view.partial_residual().count()
        ),
        (6 * PAGE as u64, 2)
    );
    assert!(view.partial_residual().readonly_native_would_refuse());
    let mut actual = vec![0; raw.len()];
    view.read_exact_at(0, &mut actual).unwrap();
    assert_eq!(actual, raw);
    drop(view);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn transient_native_probe_retry_retains_original_io_and_same_address_decisions() {
    let r = resources();
    let mut image = Image::new(fixture(1, 4));
    image.fail_once = Some((6 * PAGE as u64, 1));
    let source = Arc::new(image);
    let report = inspect_logfile_ordinary_discovery(source, ordinary_limits(), ORDER, &r).unwrap();
    let partial = report.partial_transfer().unwrap();
    assert_eq!(
        (
            partial.read_error_increments(),
            partial.retry_attempts(),
            partial.planned_remaining(),
            partial.pre_overlay_count()
        ),
        (1, 1, 0, 1)
    );
    assert!(partial.complete_native_branch());
    assert_eq!(report.stop(), NtfsLogOrdinaryStop::BoundaryObserved);
    let probes = report
        .pages()
        .iter()
        .filter(|p| p.offset() == 6 * PAGE as u64)
        .collect::<Vec<_>>();
    assert_eq!(probes.len(), 2);
    assert!(!probes[0].read_complete());
    assert!(probes[1].read_complete());
    assert_eq!(
        probes[0].partial_transition(),
        Some(NtfsLogPartialProbeTransition::ReadErrorRetry)
    );
    assert_eq!(
        probes[1].partial_transition(),
        Some(NtfsLogPartialProbeTransition::SuccessfulMismatch)
    );
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::Io);
    assert!(report.endpoint().is_none());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn native_usa_boundary_is_distinct_from_a_read_error_increment() {
    let r = resources();
    let mut raw = fixture(1, 4);
    raw[6 * PAGE + 510] ^= 1;
    let report =
        inspect_logfile_ordinary_discovery(Arc::new(Image::new(raw)), ordinary_limits(), ORDER, &r)
            .unwrap();
    let partial = report.partial_transfer().unwrap();
    assert_eq!(
        (partial.read_error_increments(), partial.pre_overlay_count()),
        (0, 0)
    );
    assert!(partial.complete_native_branch());
    assert_eq!(report.stop(), NtfsLogOrdinaryStop::BoundaryObserved);
    let probe = report.pages().last().unwrap();
    assert!(probe.usa_error());
    assert!(probe.read_complete());
    assert_eq!(
        probe.partial_transition(),
        Some(NtfsLogPartialProbeTransition::UsaBoundary)
    );
    assert!(report.stopping_error().is_none());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn partial_promoted_count_and_interrupted_arithmetic_remain_separate() {
    let r = resources();
    let mut raw = fixture(1, 4);
    install(
        &mut raw,
        6,
        &framed(1, true, 6 * PAGE, lsn(6 * PAGE + 64), u16::MAX, 2),
    );
    let mut small = ordinary_limits();
    small.work = 100000;
    let report =
        inspect_logfile_ordinary_discovery(Arc::new(Image::new(raw)), small, ORDER, &r).unwrap();
    let partial = report.partial_transfer().unwrap();
    assert_eq!(
        (partial.planned_remaining(), partial.pre_overlay_count()),
        (65533, 65533)
    );
    assert!(!partial.complete_native_branch());
    assert!(report.lookahead_trace().unwrap().arithmetic_steps < 65533);
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert!(report.endpoint().is_none());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn fast_normalization_anchor_does_not_invent_terminal_replace_page_shortcut() {
    let r = resources();
    let mut raw = fixture(2, 34);
    for (slot, target, pos) in [(2, 34, 1), (3, 35, 2), (4, 36, 3)] {
        let old = (8u64 << 16) | ((target * PAGE + 64) as u64 / 8);
        install(
            &mut raw,
            slot,
            &framed(2, false, target * PAGE, old, 3, pos),
        );
    }
    let view = inspect_logfile_read_only_overlay(
        Arc::new(Image::new(raw)),
        NtfsLogOverlayLimits {
            discovery: ordinary_limits(),
            pages: 32,
            retained_bytes: 512 << 10,
            work: 4 << 20,
        },
        ORDER,
        &r,
    )
    .unwrap();
    assert!(view.discovery().lookahead_trace().is_none());
    assert_eq!(
        view.discovery()
            .pages()
            .last()
            .unwrap()
            .partial_transition(),
        Some(NtfsLogPartialProbeTransition::SuccessfulMismatch)
    );
    assert_eq!(
        view.pages().iter().map(|p| p.target()).collect::<Vec<_>>(),
        vec![34 * PAGE as u64, 35 * PAGE as u64]
    );
    assert!(
        view.pages()
            .iter()
            .all(|p| !p.partial_consumption().consumed())
    );
    assert_eq!(view.partial_residual().count(), 0);
    drop(view);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn retry_page_ceiling_retains_original_io_and_completed_prefix_without_authority() {
    struct PersistentProbeFailure(Image);
    impl ReadAt for PersistentProbeFailure {
        fn len(&self) -> u64 {
            self.0.len()
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            if offset == 6 * PAGE as u64 {
                return Err(io::Error::other("independent persistent fixed probe error"));
            }
            self.0.read_exact_at(offset, out)
        }
    }
    let r = resources();
    let source = Arc::new(PersistentProbeFailure(Image::new(fixture(1, 4))));
    let mut limits = ordinary_limits();
    limits.pages = 5;
    let report = inspect_logfile_ordinary_discovery(source, limits, ORDER, &r).unwrap();
    assert_eq!(report.pages().len(), 5);
    assert_eq!(report.stop(), NtfsLogOrdinaryStop::PageCeiling);
    let partial = report.partial_transfer().unwrap();
    assert_eq!(
        (
            partial.retry_attempts(),
            partial.read_error_increments(),
            partial.pre_overlay_count()
        ),
        (3, 3, 3)
    );
    assert!(!partial.complete_native_branch());
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::Io);
    assert_eq!(
        report.branch_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert!(report.endpoint().is_none());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn retry_callback_cancellation_preserves_observed_raw_prefix_and_refunds() {
    let r = resources();
    let mut image = Image::new(fixture(1, 4));
    image.fail_once = Some((6 * PAGE as u64, 1));
    image.cancel_at = Some((6 * PAGE as u64, 2));
    image.cancel = r.cancellation.clone();
    let report =
        inspect_logfile_ordinary_discovery(Arc::new(image), ordinary_limits(), ORDER, &r).unwrap();
    let partial = report.partial_transfer().unwrap();
    assert_eq!(partial.read_error_increments(), 1);
    assert!(!partial.complete_native_branch());
    let observed = report.pages().last().unwrap();
    assert_eq!(observed.offset(), 6 * PAGE as u64);
    assert!(observed.read_complete());
    assert_eq!(observed.error().unwrap().kind, ErrorKind::Cancelled);
    assert!(report.endpoint().is_none());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

fn physical_fixture(first_type: u32, foreign: bool) -> Vec<u8> {
    let oldest = lsn(4 * PAGE + 64);
    let current = lsn(4 * PAGE + 112);
    let mut raw = fixture(1, 4);
    for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
        edit(restart, 0xe001, |page| {
            q(page, 56, current);
            q(page, 120, oldest);
        });
    }
    for slot in [2usize, 4] {
        let mut page = framed(1, slot == 4, 4 * PAGE, current, 1, 1);
        edit(&mut page, 0xe002, |page| {
            w(page, 24, 160);
            q(page, 64, oldest);
            w(page, 92, if foreign { 10 } else { 9 });
            d(page, 96, first_type);
            q(page, 112, current);
            w(page, 140, 9);
            d(page, 144, 1);
        });
        install(&mut raw, slot, &page);
    }
    raw
}
fn physical_view(raw: Vec<u8>, r: &Resources) -> Arc<NtfsLogReadOnlyOverlay> {
    Arc::new(
        inspect_logfile_read_only_overlay(
            Arc::new(Image::new(raw)),
            NtfsLogOverlayLimits {
                discovery: ordinary_limits(),
                pages: 32,
                retained_bytes: 512 << 10,
                work: 4 << 20,
            },
            ORDER,
            r,
        )
        .unwrap(),
    )
}
fn physical_limits() -> NtfsLogPhysicalTraversalLimits {
    NtfsLogPhysicalTraversalLimits {
        restart: limits(),
        record: NtfsLogRecordLimits {
            pages: 4,
            payload_bytes: 4096,
            work: 1 << 20,
        },
        queries: 8,
        pages: 32,
        payload_bytes: 4096,
        work: 8 << 20,
    }
}
#[test]
fn physical_traversal_retains_native_foreign_and_nonclient_skips() {
    for (kind, foreign, expected) in [
        (1, true, NtfsLogPhysicalDisposition::ForeignClient),
        (2, false, NtfsLogPhysicalDisposition::OtherEnvelope),
        (77, false, NtfsLogPhysicalDisposition::OtherEnvelope),
    ] {
        let r = resources();
        let initial = r.memory.used();
        let view = physical_view(physical_fixture(kind, foreign), &r);
        let source: Arc<dyn ReadAt> = view.clone();
        let strict = inspect_logfile_record_in_restart(
            source,
            limits(),
            physical_limits().record,
            NtfsLogRecordQuery {
                lsn: lsn(4 * PAGE + 64),
                restart_copy: 0,
            },
            &r,
        )
        .unwrap();
        if foreign || kind == 77 {
            assert!(!strict.complete());
        } else {
            assert!(strict.complete());
        }
        drop(strict);
        let report =
            inspect_logfile_overlay_physical_traversal(view, physical_limits(), &r).unwrap();
        assert!(
            report.stopping_error().is_none(),
            "{:?}",
            report.stopping_error()
        );
        assert!(report.physical_traversal_complete());
        assert_eq!(report.steps().len(), 2);
        assert_eq!(report.steps()[0].disposition(), Some(expected));
        assert_eq!(
            report.steps()[0].record().header().unwrap().record_type,
            kind
        );
        assert_eq!(
            report.steps()[0].successor(),
            Some(NtfsLogSuccessorObservation::Candidate(lsn(4 * PAGE + 112)))
        );
        assert_eq!(
            report.steps()[1].disposition(),
            Some(NtfsLogPhysicalDisposition::ClientRecord)
        );
        assert_eq!(
            report.steps()[1].successor(),
            Some(NtfsLogSuccessorObservation::OutsideObservedBounds)
        );
        assert!(!report.active_window_complete());
        assert!(!report.recovery_complete());
        drop(report);
        assert_eq!(r.memory.used(), initial);
    }
}
#[test]
fn physical_traversal_retains_failed_step_and_finite_prefix() {
    let r = resources();
    let initial = r.memory.used();
    let mut malformed = physical_fixture(1, true);
    for slot in [2usize, 4] {
        edit(
            &mut malformed[slot * PAGE..(slot + 1) * PAGE],
            0xe003,
            |page| {
                q(page, 112, lsn(4 * PAGE + 112) + 1);
            },
        );
    }
    let report = inspect_logfile_overlay_physical_traversal(
        physical_view(malformed, &r),
        physical_limits(),
        &r,
    )
    .unwrap();
    assert!(!report.physical_traversal_complete());
    assert_eq!(report.steps().len(), 2);
    assert_eq!(
        report.steps()[0].disposition(),
        Some(NtfsLogPhysicalDisposition::ForeignClient)
    );
    let failed = &report.steps()[1];
    assert!(!failed.record().complete());
    assert!(failed.record().header().is_some());
    assert_eq!(failed.record().pages().len(), 1);
    assert!(failed.stopping_error().is_some());
    assert!(failed.successor().is_none());
    drop(report);
    let mut bounded = physical_limits();
    bounded.queries = 1;
    let report = inspect_logfile_overlay_physical_traversal(
        physical_view(physical_fixture(2, false), &r),
        bounded,
        &r,
    )
    .unwrap();
    assert_eq!(report.steps().len(), 1);
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert!(!report.physical_traversal_complete());
    drop(report);
    assert_eq!(r.memory.used(), initial);
}

#[test]
fn physical_step_rejects_transient_nondecode_restart_bytes_after_restore() {
    struct EphemeralRestart {
        image: Image,
        armed: std::sync::atomic::AtomicBool,
        altered: std::sync::atomic::AtomicBool,
    }
    impl ReadAt for EphemeralRestart {
        fn len(&self) -> u64 {
            self.image.len()
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            self.image.read_exact_at(offset, out)?;
            if offset == 0
                && self.armed.load(Ordering::SeqCst)
                && !self.altered.swap(true, Ordering::SeqCst)
            {
                // Unused client-name padding: exact raw evidence changes while
                // the decoded restart context/USA framing remains identical.
                out[200] ^= 1;
            }
            Ok(())
        }
    }
    let r = resources();
    let initial = r.memory.used();
    let image = Arc::new(EphemeralRestart {
        image: Image::new(physical_fixture(1, false)),
        armed: std::sync::atomic::AtomicBool::new(false),
        altered: std::sync::atomic::AtomicBool::new(false),
    });
    let view = Arc::new(
        inspect_logfile_read_only_overlay(
            image.clone(),
            NtfsLogOverlayLimits {
                discovery: ordinary_limits(),
                pages: 32,
                retained_bytes: 512 << 10,
                work: 4 << 20,
            },
            ORDER,
            &r,
        )
        .unwrap(),
    );
    image.armed.store(true, Ordering::SeqCst);
    let report = inspect_logfile_overlay_physical_step(
        view,
        limits(),
        physical_limits().record,
        lsn(4 * PAGE + 64),
        4 << 20,
        &r,
    )
    .unwrap();
    assert!(image.altered.load(Ordering::SeqCst));
    assert!(report.record().complete());
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::StalePlan);
    assert!(report.successor().is_none());
    assert_eq!(
        report.record().restart().copies()[0].raw()[200],
        image.image.bytes[200] ^ 1
    );
    // The source has already restored baseline bytes, so original-overlay
    // guards alone pass and cannot replace retained per-query raw comparisons.
    assert!(report.overlay().check_source(4 << 20, &r).is_ok());
    drop(report);
    assert_eq!(r.memory.used(), initial);
}

fn checkpoint_fixture(override_lsn: u64, selected_restart: u64) -> Vec<u8> {
    let oldest = lsn(4 * PAGE + 64);
    let current = lsn(4 * PAGE + 224);
    let mut raw = fixture(1, 4);
    for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
        edit(restart, 0xf001, |page| {
            q(page, 56, current);
            q(page, 120, oldest);
            q(page, 128, selected_restart);
        });
    }
    for slot in [2usize, 4] {
        let mut page = framed(1, slot == 4, 4 * PAGE, current, 1, 1);
        edit(&mut page, 0xf002, |page| {
            w(page, 24, 272);
            q(page, 64, oldest);
            d(page, 88, 64);
            d(page, 96, 2);
            d(page, 112, 1); // Independent client restart payload version1.0.
            q(page, 120, override_lsn);
            q(page, 176, lsn(4 * PAGE + 176));
            w(page, 204, 9);
            d(page, 208, 1);
            q(page, 224, current);
            w(page, 252, 9);
            d(page, 256, 1);
        });
        install(&mut raw, slot, &page);
    }
    raw
}
#[test]
fn checkpoint_selection_preserves_native_override_and_read_next_before_analysis() {
    for (override_lsn, expected_anchor, expected_records, expected_selection) in [
        (
            0,
            64usize,
            vec![176usize, 224],
            NtfsLogCheckpointSelection::RestartRecordAnchor,
        ),
        (
            lsn(4 * PAGE + 176),
            176,
            vec![224],
            NtfsLogCheckpointSelection::PayloadCheckpointOverride,
        ),
        (
            lsn(4 * PAGE + 224),
            224,
            vec![],
            NtfsLogCheckpointSelection::PayloadCheckpointOverride,
        ),
    ] {
        let r = resources();
        let initial = r.memory.used();
        let traversal = inspect_logfile_overlay_physical_traversal(
            physical_view(checkpoint_fixture(override_lsn, lsn(4 * PAGE + 64)), &r),
            physical_limits(),
            &r,
        )
        .unwrap();
        assert!(traversal.physical_traversal_complete());
        let report = inspect_logfile_checkpoint_analysis_from_traversal(
            traversal,
            checkpoint_analysis_limits(),
            &r,
        );
        assert!(
            report.stopping_error().is_none(),
            "{:?}",
            report.stopping_error()
        );
        assert_eq!(report.selection(), Some(expected_selection));
        assert_eq!(
            report.restart_record().unwrap().header().unwrap().this_lsn,
            lsn(4 * PAGE + 64)
        );
        assert_eq!(
            report.analysis_anchor().unwrap().header().unwrap().this_lsn,
            lsn(4 * PAGE + expected_anchor)
        );
        assert_eq!(
            report
                .analysis_records()
                .map(|record| record.header().unwrap().this_lsn)
                .collect::<Vec<_>>(),
            expected_records
                .iter()
                .map(|at| lsn(4 * PAGE + at))
                .collect::<Vec<_>>()
        );
        assert!(!report.transaction_analysis_complete());
        assert!(!report.active_window_complete());
        assert!(!report.recovery_complete());
        drop(report);
        assert_eq!(r.memory.used(), initial);
    }
}
#[test]
fn checkpoint_missing_override_and_work_refusal_retain_source_traversal() {
    let r = resources();
    let initial = r.memory.used();
    let traversal = inspect_logfile_overlay_physical_traversal(
        physical_view(
            checkpoint_fixture(lsn(4 * PAGE + 200), lsn(4 * PAGE + 64)),
            &r,
        ),
        physical_limits(),
        &r,
    )
    .unwrap();
    let report = inspect_logfile_checkpoint_analysis_from_traversal(
        traversal,
        checkpoint_analysis_limits(),
        &r,
    );
    assert_eq!(
        report.selection(),
        Some(NtfsLogCheckpointSelection::PayloadCheckpointOverride)
    );
    assert!(report.restart_record().is_some());
    assert!(report.analysis_anchor().is_none());
    assert_eq!(report.analysis_records().count(), 0);
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::Unsupported
    );
    assert_eq!(report.traversal().steps().len(), 3);
    drop(report);
    let traversal = inspect_logfile_overlay_physical_traversal(
        physical_view(checkpoint_fixture(0, lsn(4 * PAGE + 64)), &r),
        physical_limits(),
        &r,
    )
    .unwrap();
    let maximum = traversal.work();
    let report = inspect_logfile_checkpoint_analysis_from_traversal(
        traversal,
        NtfsLogCheckpointAnalysisLimits {
            work: maximum,
            ..checkpoint_analysis_limits()
        },
        &r,
    );
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(report.traversal().steps().len(), 3);
    assert_eq!(report.analysis_records().count(), 0);
    drop(report);
    assert_eq!(r.memory.used(), initial);
}
#[test]
fn checkpoint_zero_restart_and_zero_payload_are_distinct_native_observations() {
    let r = resources();
    let initial = r.memory.used();
    let traversal = inspect_logfile_overlay_physical_traversal(
        physical_view(checkpoint_fixture(0, 0), &r),
        physical_limits(),
        &r,
    )
    .unwrap();
    let report = inspect_logfile_checkpoint_analysis_from_traversal(
        traversal,
        checkpoint_analysis_limits(),
        &r,
    );
    assert!(report.stopping_error().is_none());
    assert_eq!(
        report.selection(),
        Some(NtfsLogCheckpointSelection::NoRestartLsn)
    );
    assert!(report.restart_record().is_none());
    assert_eq!(report.analysis_records().count(), 0);
    assert_eq!(report.traversal().steps().len(), 3); // No claim of an empty physical log.
    drop(report);
    let mut raw = physical_fixture(2, false);
    for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
        edit(restart, 0xf003, |page| q(page, 128, lsn(4 * PAGE + 64)));
    }
    let traversal =
        inspect_logfile_overlay_physical_traversal(physical_view(raw, &r), physical_limits(), &r)
            .unwrap();
    let report = inspect_logfile_checkpoint_analysis_from_traversal(
        traversal,
        checkpoint_analysis_limits(),
        &r,
    );
    assert!(report.stopping_error().is_none());
    assert_eq!(
        report.selection(),
        Some(NtfsLogCheckpointSelection::EmptyRestartPayload)
    );
    assert!(report.restart_record().is_some());
    assert!(report.analysis_anchor().is_none());
    assert_eq!(report.analysis_records().count(), 0);
    drop(report);
    assert_eq!(r.memory.used(), initial);
}

#[test]
fn checkpoint_unknown_version_and_unvisited_restart_refuse_without_substitution() {
    let r = resources();
    let initial = r.memory.used();
    for unknown_version in [false, true] {
        let selected = if unknown_version {
            lsn(4 * PAGE + 64)
        } else {
            lsn(4 * PAGE + 200)
        };
        let mut raw = checkpoint_fixture(0, selected);
        if unknown_version {
            for slot in [2usize, 4] {
                edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xf004, |page| {
                    d(page, 112, 2)
                });
            }
        }
        let traversal = inspect_logfile_overlay_physical_traversal(
            physical_view(raw, &r),
            physical_limits(),
            &r,
        )
        .unwrap();
        let report = inspect_logfile_checkpoint_analysis_from_traversal(
            traversal,
            checkpoint_analysis_limits(),
            &r,
        );
        assert_eq!(
            report.stopping_error().unwrap().kind,
            if unknown_version {
                ErrorKind::Unsupported
            } else {
                ErrorKind::InvalidData
            }
        );
        assert_eq!(report.traversal().steps().len(), 3);
        assert!(report.analysis_anchor().is_none());
        assert_eq!(report.analysis_records().count(), 0);
        assert!(report.restart_record().is_some());
        drop(report);
    }
    assert_eq!(r.memory.used(), initial);
}

fn checkpoint_analysis_limits() -> NtfsLogCheckpointAnalysisLimits {
    NtfsLogCheckpointAnalysisLimits {
        restart: limits(),
        record: physical_limits().record,
        pages: 64,
        payload_bytes: 8192,
        work: 16 << 20,
    }
}

fn direct_checkpoint_fixture() -> (Vec<u8>, u64) {
    let restart_lsn = (8u64 << 16) | ((6 * PAGE + 64) as u64 / 8);
    let mut raw = physical_fixture(1, false);
    for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
        edit(restart, 0xf101, |page| q(page, 128, restart_lsn));
    }
    let mut page = framed(1, true, 6 * PAGE, restart_lsn, 1, 1);
    edit(&mut page, 0xf102, |page| {
        w(page, 24, 176);
        d(page, 88, 64);
        d(page, 96, 2);
        d(page, 112, 1);
        q(page, 120, lsn(4 * PAGE + 64));
    });
    install(&mut raw, 6, &page);
    (raw, restart_lsn)
}
#[test]
fn checkpoint_direct_selected_restart_outside_oldest_uses_exact_source_and_override() {
    let r = resources();
    let initial = r.memory.used();
    let (raw, selected) = direct_checkpoint_fixture();
    assert!(selected < lsn(4 * PAGE + 64));
    let traversal =
        inspect_logfile_overlay_physical_traversal(physical_view(raw, &r), physical_limits(), &r)
            .unwrap();
    assert!(traversal.physical_traversal_complete());
    assert_eq!(traversal.steps().len(), 2);
    assert!(
        traversal
            .steps()
            .iter()
            .all(|s| s.record().header().unwrap().this_lsn != selected)
    );
    let prior_pages = traversal.pages();
    let report = inspect_logfile_checkpoint_analysis_from_traversal(
        traversal,
        checkpoint_analysis_limits(),
        &r,
    );
    assert!(
        report.stopping_error().is_none(),
        "{:?}",
        report.stopping_error()
    );
    assert!(report.direct_restart_query());
    assert_eq!(
        report.restart_record().unwrap().header().unwrap().this_lsn,
        selected
    );
    assert_eq!(
        report.restart_record().unwrap().pages()[0].offset(),
        (6 * PAGE) as u64
    );
    assert_eq!(
        report.selection(),
        Some(NtfsLogCheckpointSelection::PayloadCheckpointOverride)
    );
    assert_eq!(
        report.analysis_anchor().unwrap().header().unwrap().this_lsn,
        lsn(4 * PAGE + 64)
    );
    assert_eq!(
        report
            .analysis_records()
            .map(|record| record.header().unwrap().this_lsn)
            .collect::<Vec<_>>(),
        vec![lsn(4 * PAGE + 112)]
    );
    assert_eq!(report.pages(), prior_pages + 3);
    assert_eq!(report.payload_bytes(), 64);
    assert!(!report.active_window_complete());
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), initial);
}
#[test]
fn checkpoint_direct_lookup_obeys_aggregate_pages_and_retains_failed_payload_query() {
    let r = resources();
    let initial = r.memory.used();
    for fail_payload in [false, true] {
        let (raw, _) = direct_checkpoint_fixture();
        let traversal = inspect_logfile_overlay_physical_traversal(
            physical_view(raw, &r),
            physical_limits(),
            &r,
        )
        .unwrap();
        let mut ceiling = checkpoint_analysis_limits();
        if fail_payload {
            ceiling.payload_bytes = 1;
        } else {
            ceiling.pages = traversal.pages() + 1;
        }
        let report = inspect_logfile_checkpoint_analysis_from_traversal(traversal, ceiling, &r);
        assert_eq!(
            report.stopping_error().unwrap().kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(report.direct_restart_query(), fail_payload);
        if fail_payload {
            assert!(!report.restart_record().unwrap().complete());
            assert!(report.restart_record().unwrap().header().is_some());
            assert_eq!(report.restart_record().unwrap().pages().len(), 1);
        }
        assert!(report.analysis_anchor().is_none());
        assert_eq!(report.analysis_records().count(), 0);
        drop(report);
    }
    assert_eq!(r.memory.used(), initial);
}

#[test]
fn checkpoint_direct_restart_retains_exact_raw_query_guard_after_source_restores() {
    struct EphemeralCheckpoint {
        image: Image,
        armed: std::sync::atomic::AtomicBool,
        altered: std::sync::atomic::AtomicBool,
    }
    impl ReadAt for EphemeralCheckpoint {
        fn len(&self) -> u64 {
            self.image.len()
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            self.image.read_exact_at(offset, out)?;
            if offset == (6 * PAGE) as u64
                && self.armed.load(Ordering::SeqCst)
                && !self.altered.swap(true, Ordering::SeqCst)
            {
                out[180] ^= 1;
            }
            Ok(())
        }
    }
    let r = resources();
    let initial = r.memory.used();
    let (raw, _) = direct_checkpoint_fixture();
    let image = Arc::new(EphemeralCheckpoint {
        image: Image::new(raw),
        armed: std::sync::atomic::AtomicBool::new(false),
        altered: std::sync::atomic::AtomicBool::new(false),
    });
    let view = Arc::new(
        inspect_logfile_read_only_overlay(
            image.clone(),
            NtfsLogOverlayLimits {
                discovery: ordinary_limits(),
                pages: 32,
                retained_bytes: 512 << 10,
                work: 4 << 20,
            },
            ORDER,
            &r,
        )
        .unwrap(),
    );
    let traversal =
        inspect_logfile_overlay_physical_traversal(view.clone(), physical_limits(), &r).unwrap();
    image.armed.store(true, Ordering::SeqCst);
    let report = inspect_logfile_checkpoint_analysis_from_traversal(
        traversal,
        checkpoint_analysis_limits(),
        &r,
    );
    assert!(report.direct_restart_query());
    assert!(report.restart_record().unwrap().complete());
    assert!(image.altered.load(Ordering::SeqCst));
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::StalePlan);
    assert_eq!(report.analysis_records().count(), 0);
    assert!(view.check_source(4 << 20, &r).is_ok());
    drop(report);
    drop(view);
    assert_eq!(r.memory.used(), initial);
}

fn replay_limits() -> NtfsLogReplayAnalysisLimits {
    NtfsLogReplayAnalysisLimits {
        dumps: NtfsLogCheckpointDumpLimits {
            restart: limits(),
            record: physical_limits().record,
            table: NtfsLogRestartTableLimits {
                entries: 32,
                bytes: 8192,
                work: 1 << 20,
            },
            queries: 5,
            pages: 32,
            payload_bytes: 8192,
            work: 8 << 20,
        },
        pages: 128,
        payload_bytes: 32768,
        transactions: 16,
        records: 32,
        work: 32 << 20,
    }
}
fn native_client(redo: u16, undo: u16) -> Vec<u8> {
    let mut payload = vec![0; 40];
    w(&mut payload, 0, redo);
    w(&mut payload, 2, undo);
    w(&mut payload, 4, 40);
    w(&mut payload, 8, 40);
    payload
}
fn transaction_suffix_fixture() -> Vec<u8> {
    let starts = [176usize, 264, 352, 440, 528, 616, 704];
    let ops = [
        (0u16, 0u16),
        (25, 0),
        (26, 0),
        (24, 0),
        (27, 0),
        (0, 1),
        (35, 0),
    ];
    let mut raw = checkpoint_fixture(0, lsn(4 * PAGE + 64));
    let current = lsn(4 * PAGE + 704);
    for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
        edit(restart, 0xf201, |page| {
            q(page, 56, current);
            d(page, 88, 40);
        });
    }
    for slot in [2usize, 4] {
        let mut page = framed(1, slot == 4, 4 * PAGE, current, 1, 1);
        edit(&mut page, 0xf202, |page| {
            w(page, 24, 792);
            q(page, 64, lsn(4 * PAGE + 64));
            d(page, 88, 64);
            d(page, 96, 2);
            d(page, 112, 1);
            for (i, (start, (redo, undo))) in starts.iter().zip(ops.iter()).enumerate() {
                q(page, *start, lsn(4 * PAGE + start));
                q(
                    page,
                    *start + 8,
                    if i == 0 {
                        0
                    } else {
                        lsn(4 * PAGE + starts[i - 1])
                    },
                );
                q(
                    page,
                    *start + 16,
                    if *redo == 24 {
                        lsn(4 * PAGE + 176)
                    } else if *undo == 1 {
                        lsn(4 * PAGE + 264)
                    } else {
                        0
                    },
                );
                d(page, *start + 24, 40);
                w(page, *start + 28, 9);
                d(page, *start + 32, 1);
                d(page, *start + 36, if i == 6 { 64 } else { 24 });
                page[*start + 48..*start + 88].copy_from_slice(&native_client(*redo, *undo));
            }
        });
        install(&mut raw, slot, &page);
    }
    raw
}
#[test]
fn replay_analysis_derives_native_transaction_prefix_without_reordering_or_replay_authority() {
    let r = resources();
    let initial = r.memory.used();
    let traversal = inspect_logfile_overlay_physical_traversal(
        physical_view(transaction_suffix_fixture(), &r),
        physical_limits(),
        &r,
    )
    .unwrap();
    assert!(traversal.physical_traversal_complete());
    let selected = inspect_logfile_checkpoint_analysis_from_traversal(
        traversal,
        checkpoint_analysis_limits(),
        &r,
    );
    assert!(selected.stopping_error().is_none());
    let report = inspect_logfile_replay_analysis(selected, replay_limits(), &r).unwrap();
    assert!(
        report.stopping_error().is_none(),
        "{:?}",
        report.stopping_error()
    );
    assert!(report.transaction_fields_complete());
    assert_eq!(
        report
            .records()
            .iter()
            .map(NtfsLogAnalysisRecord::redo_operation)
            .collect::<Vec<_>>(),
        vec![0, 25, 26, 24, 27, 0, 35]
    );
    assert_eq!(report.transactions().len(), 2);
    assert_eq!(report.records()[1].state_after(), 2);
    assert_eq!(report.records()[2].state_after(), 3);
    assert_eq!(report.records()[3].undo_next_after(), lsn(4 * PAGE + 176));
    assert!(!report.records()[4].allocated_after());
    assert_eq!(report.records()[5].state_after(), 1);
    assert_eq!(report.records()[5].first_lsn_after(), lsn(4 * PAGE + 616));
    assert_eq!(report.records()[5].undo_next_after(), lsn(4 * PAGE + 264));
    let first = &report.transactions()[0];
    assert_eq!(first.id(), 24);
    assert!(first.allocated());
    assert_eq!(first.state(), 1); // Forget followed by actual reallocation.
    assert_eq!(first.first_lsn(), lsn(4 * PAGE + 616));
    assert_eq!(first.previous_lsn(), lsn(4 * PAGE + 616));
    assert_eq!(first.undo_next_lsn(), lsn(4 * PAGE + 264)); // Actual compensation undo link.
    assert_eq!(first.first_dependency(), NtfsLogAnalysisLink::Visited(6));
    assert_eq!(first.undo_dependency(), NtfsLogAnalysisLink::Visited(2));
    assert_eq!(
        report.records()[6].previous(),
        NtfsLogAnalysisLink::DifferentTransaction(6)
    );
    assert!(report.records()[6].remaining_effects());
    assert!(!report.transaction_analysis_complete());
    assert!(!report.active_window_complete());
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), initial);
}

fn native_tables_fixture() -> Vec<u8> {
    let current = lsn(9 * PAGE + 64);
    let mut raw = fixture(1, 9);
    for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
        edit(restart, 0xf301, |page| {
            q(page, 56, current);
            d(page, 88, 40);
            q(page, 120, lsn(4 * PAGE + 64));
            q(page, 128, lsn(8 * PAGE + 64));
        });
    }
    for physical in 4usize..=9 {
        let record_lsn = lsn(physical * PAGE + 64);
        let (kind, payload) = if physical == 8 {
            let mut checkpoint = vec![0; 64];
            d(&mut checkpoint, 0, 1);
            q(&mut checkpoint, 16, lsn(7 * PAGE + 64));
            q(&mut checkpoint, 24, lsn(6 * PAGE + 64));
            q(&mut checkpoint, 32, lsn(5 * PAGE + 64));
            q(&mut checkpoint, 40, lsn(4 * PAGE + 64));
            d(&mut checkpoint, 48, 64);
            d(&mut checkpoint, 52, 8);
            d(&mut checkpoint, 56, 56);
            d(&mut checkpoint, 60, 64);
            (2, checkpoint)
        } else {
            let operation = match physical {
                4 => 32,
                5 => 31,
                6 => 30,
                7 => 29,
                _ => 0,
            };
            let mut client = native_client(operation, 0);
            if physical == 6 {
                client.extend_from_slice(&[0; 8]);
                w(&mut client, 4, 48); // Native names begins at lrh_length40 instead.
            } else if physical != 9 {
                let mut table = vec![0; if physical == 5 { 56 } else { 64 }];
                w(&mut table, 0, if physical == 5 { 32 } else { 40 });
                w(&mut table, 2, 1);
                if physical != 4 {
                    d(&mut table, 12, u32::MAX);
                    d(&mut table, 16, 24);
                    d(&mut table, 20, 24);
                }
                if physical == 4 {
                    w(&mut table, 2, 1);
                    w(&mut table, 4, 1);
                    d(&mut table, 24, u32::MAX);
                    table[28] = 2;
                    q(&mut table, 32, record_lsn);
                    q(&mut table, 40, record_lsn);
                }
                w(&mut client, 6, 24); // Native table loader takes through payload END.
                client.extend_from_slice(&table);
            }
            (1, client)
        };
        for slot in if physical == 9 {
            vec![2usize, 9]
        } else {
            vec![physical]
        } {
            let mut page = framed(1, slot != 2, physical * PAGE, record_lsn, 1, 1);
            edit(&mut page, 0xf302, |page| {
                w(page, 24, (64 + 48 + payload.len()) as u16);
                d(page, 88, payload.len() as u32);
                d(page, 96, kind);
                d(page, 100, 24);
                page[112..112 + payload.len()].copy_from_slice(&payload);
            });
            install(&mut raw, slot, &page);
        }
    }
    raw
}
#[test]
fn replay_native_table_read_order_body_lengths_and_typed_initial_transactions() {
    struct OrderedSource {
        image: Image,
        armed: std::sync::atomic::AtomicBool,
        offsets: std::sync::Mutex<Vec<u64>>,
    }
    impl ReadAt for OrderedSource {
        fn len(&self) -> u64 {
            self.image.len()
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            if self.armed.load(Ordering::SeqCst) && offset >= (4 * PAGE) as u64 {
                self.offsets.lock().unwrap().push(offset);
            }
            self.image.read_exact_at(offset, out)
        }
    }
    let r = resources();
    let initial = r.memory.used();
    let image = Arc::new(OrderedSource {
        image: Image::new(native_tables_fixture()),
        armed: std::sync::atomic::AtomicBool::new(false),
        offsets: std::sync::Mutex::new(Vec::new()),
    });
    let view = Arc::new(
        inspect_logfile_read_only_overlay(
            image.clone(),
            NtfsLogOverlayLimits {
                discovery: ordinary_limits(),
                pages: 32,
                retained_bytes: 512 << 10,
                work: 4 << 20,
            },
            ORDER,
            &r,
        )
        .unwrap(),
    );
    let traversal =
        inspect_logfile_overlay_physical_traversal(view, physical_limits(), &r).unwrap();
    assert!(traversal.physical_traversal_complete());
    let checkpoint = inspect_logfile_checkpoint_analysis_from_traversal(
        traversal,
        checkpoint_analysis_limits(),
        &r,
    );
    assert!(checkpoint.stopping_error().is_none());
    image.armed.store(true, Ordering::SeqCst);
    let report = inspect_logfile_replay_analysis(checkpoint, replay_limits(), &r).unwrap();
    assert!(
        report.stopping_error().is_none(),
        "{:?}",
        report.stopping_error()
    );
    assert!(report.transaction_fields_complete());
    assert_eq!(
        &image.offsets.lock().unwrap()[..5],
        &[
            8 * PAGE as u64,
            4 * PAGE as u64,
            5 * PAGE as u64,
            6 * PAGE as u64,
            7 * PAGE as u64
        ]
    );
    let dumps = report.dumps().unwrap();
    assert_eq!(
        inspect_ntfs_log_client_record(dumps.dumps()[3].record().unwrap())
            .unwrap()
            .redo()
            .len(),
        24
    );
    assert_eq!(
        inspect_ntfs_log_client_record(dumps.dumps()[1].record().unwrap())
            .unwrap()
            .redo()
            .len(),
        0
    );
    assert_eq!(dumps.transaction_entry(0).unwrap().unwrap().state, 2);
    assert_eq!(dumps.dumps()[3].reference_bytes_match(), Some(true));
    assert_eq!(dumps.dumps()[1].reference_bytes_match(), Some(true));
    let entry = &report.transactions()[0];
    assert_eq!(entry.initial_slot(), Some(0));
    assert_eq!(entry.state(), 2);
    assert_eq!(entry.first_lsn(), lsn(4 * PAGE + 64));
    assert_eq!(entry.previous_lsn(), lsn(9 * PAGE + 64));
    assert_eq!(entry.undo_next_lsn(), lsn(9 * PAGE + 64));
    assert_eq!(report.records().len(), 1);
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), initial);
}

#[test]
fn replay_analysis_limits_preserve_native_prefix_and_table_extension_bound() {
    let r = resources();
    let initial = r.memory.used();
    for bound in 0..3 {
        let traversal = inspect_logfile_overlay_physical_traversal(
            physical_view(transaction_suffix_fixture(), &r),
            physical_limits(),
            &r,
        )
        .unwrap();
        let selected = inspect_logfile_checkpoint_analysis_from_traversal(
            traversal,
            checkpoint_analysis_limits(),
            &r,
        );
        let mut ceiling = replay_limits();
        match bound {
            0 => ceiling.records = 2,
            1 => ceiling.transactions = 1,
            _ => ceiling.dumps.table.entries = 1,
        }
        let report = inspect_logfile_replay_analysis(selected, ceiling, &r).unwrap();
        assert_eq!(
            report.stopping_error().unwrap().kind,
            ErrorKind::BudgetExhausted
        );
        assert!(!report.transaction_fields_complete());
        assert_eq!(report.records().len(), if bound == 0 { 2 } else { 6 });
        assert_eq!(report.transactions().len(), 1);
        assert_eq!(
            report.transactions()[0].state(),
            if bound == 0 { 2 } else { 1 }
        );
        drop(report);
    }
    let mut raw = transaction_suffix_fixture();
    for slot in [2usize, 4] {
        edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xf401, |page| {
            w(page, 176 + 48, 7)
        });
    }
    let traversal =
        inspect_logfile_overlay_physical_traversal(physical_view(raw, &r), physical_limits(), &r)
            .unwrap();
    let selected = inspect_logfile_checkpoint_analysis_from_traversal(
        traversal,
        checkpoint_analysis_limits(),
        &r,
    );
    let report = inspect_logfile_replay_analysis(selected, replay_limits(), &r).unwrap();
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::InvalidData
    ); // Native required target absent.
    assert!(report.records().is_empty());
    assert!(
        report.checkpoint().traversal().steps()[1]
            .record()
            .complete()
    );
    assert!(!report.transaction_fields_complete());
    drop(report);
    assert_eq!(r.memory.used(), initial);
}

#[test]
fn replay_native_ignored_declared_lengths_do_not_inherit_public_range_refusal() {
    let r = resources();
    let initial = r.memory.used();
    let mut raw = native_tables_fixture();
    for slot in [4usize, 5, 6, 7, 2, 9] {
        edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xf501, |page| {
            // Native check_log_rec checks alignment, not these ignored bounds.
            w(page, 118, u16::MAX);
            w(page, 120, 0xfff8);
            w(page, 122, u16::MAX);
            if matches!(slot, 6 | 2 | 9) {
                w(page, 116, 0xfff8);
            }
        });
    }
    let traversal =
        inspect_logfile_overlay_physical_traversal(physical_view(raw, &r), physical_limits(), &r)
            .unwrap();
    assert!(traversal.physical_traversal_complete());
    let selected = inspect_logfile_checkpoint_analysis_from_traversal(
        traversal,
        checkpoint_analysis_limits(),
        &r,
    );
    let report = inspect_logfile_replay_analysis(selected, replay_limits(), &r).unwrap();
    assert!(
        report.stopping_error().is_none(),
        "{:?}",
        report.stopping_error()
    );
    assert!(report.transaction_fields_complete());
    let dumps = report.dumps().unwrap();
    for dump in dumps.dumps() {
        assert!(inspect_ntfs_log_client_record(dump.record().unwrap()).is_err());
    }
    assert_eq!(dumps.transaction_entry(0).unwrap().unwrap().state, 2);
    assert_eq!(dumps.dumps()[1].reference_bytes_match(), Some(true));
    assert_eq!(report.records().len(), 1);
    let actual =
        report.checkpoint().traversal().steps()[report.records()[0].physical_index()].record();
    assert!(inspect_ntfs_log_client_record(actual).is_err());
    assert_eq!(report.records()[0].redo_operation(), 0);
    assert!(!report.transaction_analysis_complete());
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), initial);
}

#[path = "fixtures/ntfs_clean.rs"]
mod dirty_native_volume_fixture;
fn dirty_suffix_fixture() -> Vec<u8> {
    let starts = [176usize, 264, 352, 456];
    let ops = [8u16, 23, 10, 0];
    let mut raw = checkpoint_fixture(0, lsn(4 * PAGE + 64));
    let current = lsn(4 * PAGE + 456);
    for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
        edit(restart, 0xe101, |page| {
            q(page, 56, current);
            d(page, 88, 40);
        });
    }
    for slot in [2usize, 4] {
        let mut page = framed(1, slot == 4, 4 * PAGE, current, 1, 1);
        edit(&mut page, 0xe102, |page| {
            w(page, 24, 544);
            q(page, 64, lsn(4 * PAGE + 64));
            d(page, 88, 64);
            d(page, 96, 2);
            d(page, 112, 1);
            for (i, start) in starts.iter().copied().enumerate() {
                let mut payload = native_client(ops[i], 0);
                w(&mut payload, 12, 24);
                if i < 2 {
                    w(&mut payload, 14, 1);
                    q(&mut payload, 24, 0);
                    q(&mut payload, 32, if i == 0 { 100 } else { 200 });
                }
                if i == 2 {
                    w(&mut payload, 6, 16);
                    payload.extend_from_slice(&200u64.to_le_bytes());
                    payload.extend_from_slice(&1u64.to_le_bytes());
                }
                q(page, start, lsn(4 * PAGE + start));
                q(
                    page,
                    start + 8,
                    if i == 0 {
                        0
                    } else {
                        lsn(4 * PAGE + starts[i - 1])
                    },
                );
                d(page, start + 24, payload.len() as u32);
                w(page, start + 28, 9);
                d(page, start + 32, 1);
                d(page, start + 36, 24);
                page[start + 48..start + 48 + payload.len()].copy_from_slice(&payload);
            }
        });
        install(&mut raw, slot, &page);
    }
    raw
}
fn dirty_native_volume(raw: Vec<u8>) -> Vec<u8> {
    use dirty_native_volume_fixture::{name_value, nonresident, put, resident};
    let mut volume = dirty_native_volume_fixture::ntfs_audit_seed();
    let data = nonresident(
        &[0x22, 0, 2, 0, 2, 0],
        512,
        LENGTH as u64,
        LENGTH as u64,
        false,
    );
    put(
        &mut volume,
        2,
        &[
            resident(0x10, &[0; 48], 0),
            resident(0x30, &name_value("$LogFile", 5), 2),
            data,
        ],
        false,
        1,
    );
    volume[512 * 512..512 * 512 + LENGTH].copy_from_slice(&raw);
    let mirror = volume[2048..6144].to_vec();
    volume[500 * 512..508 * 512].copy_from_slice(&mirror);
    volume
}
fn dirty_native_context(raw: Vec<u8>, r: &Resources) -> NtfsLogNativeAnalysisContext {
    dirty_native_context_source(Arc::new(Image::new(dirty_native_volume(raw))), r)
}
fn dirty_native_context_source(
    source: Arc<dyn ReadAt>,
    r: &Resources,
) -> NtfsLogNativeAnalysisContext {
    inspect_ntfs_log_native_analysis_context(
        source,
        partmgr::fs_ntfs::NtfsReadLimits {
            attributes: 32,
            runs: 64,
            names: 255,
        },
        partmgr::fs_ntfs::NtfsStreamLimits {
            extension_records: 8,
            list_entries: 64,
            list_bytes: 4096,
            attributes: 32,
            runs: 64,
            work: 1_000_000,
        },
        NtfsLogNativeContextLimits {
            reads: 256,
            bytes: 262144,
            work: 1_000_000,
        },
        r,
    )
    .unwrap()
}
fn dirty_replay(
    context: &NtfsLogNativeAnalysisContext,
    r: &Resources,
) -> NtfsLogReplayAnalysisReport {
    let overlay = Arc::new(
        inspect_logfile_read_only_overlay(
            context.logfile_source(),
            NtfsLogOverlayLimits {
                discovery: ordinary_limits(),
                pages: 32,
                retained_bytes: 512 << 10,
                work: 4 << 20,
            },
            ORDER,
            r,
        )
        .unwrap(),
    );
    let traversal =
        inspect_logfile_overlay_physical_traversal(overlay, physical_limits(), r).unwrap();
    let selected = inspect_logfile_checkpoint_analysis_from_traversal(
        traversal,
        checkpoint_analysis_limits(),
        r,
    );
    inspect_logfile_replay_analysis(selected, replay_limits(), r).unwrap()
}
#[test]
fn native_dirty_update_hotfix_delete_follow_exact_source_suffix_and_geometry() {
    let r = resources();
    let context = dirty_native_context(dirty_suffix_fixture(), &r);
    let replay = dirty_replay(&context, &r);
    assert!(replay.transaction_fields_complete());
    let report = inspect_logfile_native_dirty_analysis(
        context,
        replay,
        NtfsLogDirtyAnalysisLimits {
            entries: 64,
            lcns: 8,
            work: 64 << 20,
        },
        &r,
    )
    .unwrap();
    assert!(
        report.dirty_fields_complete(),
        "{:?}",
        report.stopping_error()
    );
    assert_eq!(report.processed_records(), 4);
    let table = report.dirty_table_bytes();
    assert_eq!(u16::from_le_bytes(table[..2].try_into().unwrap()), 96);
    assert_eq!(u16::from_le_bytes(table[2..4].try_into().unwrap()), 32);
    assert_eq!(u16::from_le_bytes(table[4..6].try_into().unwrap()), 1);
    assert_eq!(
        u64::from_le_bytes(table[48..56].try_into().unwrap()),
        lsn(4 * PAGE + 176)
    );
    assert_eq!(u64::from_le_bytes(table[56..64].try_into().unwrap()), 0);
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn native_dirty_context_rejects_equal_byte_different_source_and_finite_native_allocation() {
    let r = resources();
    let context = dirty_native_context(dirty_suffix_fixture(), &r);
    let other = dirty_native_context(dirty_suffix_fixture(), &r);
    let replay = dirty_replay(&other, &r);
    let result = inspect_logfile_native_dirty_analysis(
        context,
        replay,
        NtfsLogDirtyAnalysisLimits {
            entries: 64,
            lcns: 8,
            work: 64 << 20,
        },
        &r,
    );
    match result {
        Err(e) => assert_eq!(e.kind, ErrorKind::StalePlan),
        Ok(_) => panic!("foreign native geometry context accepted"),
    };
    drop(other);
    assert_eq!(r.memory.used(), 0);
    let context = dirty_native_context(dirty_suffix_fixture(), &r);
    let replay = dirty_replay(&context, &r);
    let report = inspect_logfile_native_dirty_analysis(
        context,
        replay,
        NtfsLogDirtyAnalysisLimits {
            entries: 31,
            lcns: 8,
            work: 64 << 20,
        },
        &r,
    )
    .unwrap();
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(report.processed_records(), 0);
    assert!(!report.dirty_fields_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

fn open_suffix_fixture() -> Vec<u8> {
    let starts = [176usize, 312, 400];
    let mut raw = checkpoint_fixture(0, lsn(4 * PAGE + 64));
    let current = lsn(4 * PAGE + 400);
    for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
        edit(restart, 0xd101, |page| {
            q(page, 56, current);
            d(page, 88, 40);
        });
    }
    for slot in [2usize, 4] {
        let mut page = framed(1, slot == 4, 4 * PAGE, current, 1, 1);
        edit(&mut page, 0xd102, |page| {
            w(page, 24, 488);
            q(page, 64, lsn(4 * PAGE + 64));
            d(page, 88, 64);
            d(page, 96, 2);
            d(page, 112, 1);
            for (i, start) in starts.iter().copied().enumerate() {
                let mut payload = native_client([28, 8, 0][i], 0);
                w(&mut payload, 12, 24);
                if i == 0 {
                    let mut entry = [0; 40];
                    d(&mut entry, 0, u32::MAX);
                    d(&mut entry, 8, 0x80);
                    q(&mut entry, 16, (7u64 << 48) | 2);
                    q(&mut entry, 24, lsn(4 * PAGE + 176));
                    payload.extend_from_slice(&entry);
                    payload.extend_from_slice(&[b'n', 0, b'a', 0, b'm', 0, b'e', 0]);
                    w(&mut payload, 6, 40);
                    w(&mut payload, 8, 80);
                    w(&mut payload, 10, 8);
                }
                if i == 1 {
                    w(&mut payload, 14, 1);
                    q(&mut payload, 32, 100);
                }
                q(page, start, lsn(4 * PAGE + start));
                q(
                    page,
                    start + 8,
                    if i == 0 {
                        0
                    } else {
                        lsn(4 * PAGE + starts[i - 1])
                    },
                );
                d(page, start + 24, payload.len() as u32);
                w(page, start + 28, 9);
                d(page, start + 32, 1);
                d(page, start + 36, 24);
                page[start + 48..start + 48 + payload.len()].copy_from_slice(&payload);
            }
        });
        install(&mut raw, slot, &page);
    }
    raw
}
#[test]
fn native_open_name_effects_do_not_truncate_later_dirty_updates() {
    let r = resources();
    let context = dirty_native_context(open_suffix_fixture(), &r);
    let replay = dirty_replay(&context, &r);
    let report = inspect_logfile_native_open_analysis(
        context,
        replay,
        NtfsLogDirtyAnalysisLimits {
            entries: 64,
            lcns: 8,
            work: 64 << 20,
        },
        NtfsLogOpenAnalysisLimits {
            entries: 64,
            entry_bytes: 40,
            name_bytes: 1024,
        },
        &r,
    )
    .unwrap();
    assert!(
        report.dirty_fields_complete(),
        "{:?}",
        report.stopping_error()
    );
    assert_eq!(report.processed_records(), 3);
    let open = report.open_attributes().unwrap();
    assert_eq!(open.native_name_units(0), Some(4));
    assert_eq!(
        open.name_bytes(0),
        Some(&[b'n', 0, b'a', 0, b'm', 0, b'e', 0][..])
    );
    let table = open.table_bytes();
    assert_eq!(table[37], 1);
    assert_eq!(&table[56..64], &[0; 8]);
    assert_eq!(u16::from_le_bytes(table[4..6].try_into().unwrap()), 1);
    assert_eq!(
        u64::from_le_bytes(report.dirty_table_bytes()[56..64].try_into().unwrap()),
        100
    );
    assert!(!report.transaction_analysis_complete());
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn native_open_name_peak_budget_refuses_with_retained_source_and_no_recovery_authority() {
    let r = resources();
    let context = dirty_native_context(open_suffix_fixture(), &r);
    let replay = dirty_replay(&context, &r);
    let report = inspect_logfile_native_open_analysis(
        context,
        replay,
        NtfsLogDirtyAnalysisLimits {
            entries: 64,
            lcns: 8,
            work: 64 << 20,
        },
        NtfsLogOpenAnalysisLimits {
            entries: 64,
            entry_bytes: 40,
            name_bytes: 7,
        },
        &r,
    )
    .unwrap();
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(report.processed_records(), 0);
    assert!(report.open_attributes().is_some());
    assert!(!report.dirty_fields_complete());
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_initial_names_overlay_in_source_order_and_last_duplicate_wins() {
    let r = resources();
    let mut raw = native_tables_fixture();
    let mut names = native_client(30, 0);
    names.extend_from_slice(&[24, 0, 2, 0, b'a', 0, 24, 0, 2, 0, b'b', 0, 0, 0, 0, 0]);
    let mut open = native_client(29, 0);
    let mut table = vec![0; 64];
    w(&mut table, 0, 40);
    w(&mut table, 2, 1);
    w(&mut table, 4, 1);
    d(&mut table, 24, u32::MAX);
    d(&mut table, 32, 0x80);
    q(&mut table, 40, (7u64 << 48) | 2);
    table[38] = 50;
    open.extend_from_slice(&table);
    for (physical, payload) in [(6usize, names), (7, open)] {
        let page = &mut raw[physical * PAGE..(physical + 1) * PAGE];
        edit(page, 0xd201, |page| {
            w(page, 24, (64 + 48 + payload.len()) as u16);
            d(page, 88, payload.len() as u32);
            page[112..112 + payload.len()].copy_from_slice(&payload);
        });
    }
    let context = dirty_native_context(raw, &r);
    let replay = dirty_replay(&context, &r);
    let report = inspect_logfile_native_open_analysis(
        context,
        replay,
        NtfsLogDirtyAnalysisLimits {
            entries: 64,
            lcns: 8,
            work: 64 << 20,
        },
        NtfsLogOpenAnalysisLimits {
            entries: 64,
            entry_bytes: 40,
            name_bytes: 64,
        },
        &r,
    )
    .unwrap();
    assert!(
        report.dirty_fields_complete(),
        "{:?}",
        report.stopping_error()
    );
    let open = report.open_attributes().unwrap();
    assert_eq!(open.initial_names_stop(), NtfsLogNameStop::Terminator);
    assert_eq!(open.native_name_units(0), Some(1));
    assert_eq!(open.name_bytes(0), Some(&[b'b', 0][..]));
    assert_eq!(open.table_bytes()[37], 2);
    assert_eq!(&open.table_bytes()[56..64], &[0; 8]);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_initial_name_full_source_bound_distinguishes_trailing_nonslot_from_truncation() {
    for trailing in [0usize, 40] {
        let r = resources();
        let mut raw = native_tables_fixture();
        let mut names = native_client(30, 0);
        names.extend_from_slice(&[64, 0, 2, 0, b'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut open = native_client(29, 0);
        let mut table = vec![0; 64 + trailing];
        w(&mut table, 0, 40);
        w(&mut table, 2, 1);
        w(&mut table, 4, 1);
        d(&mut table, 24, u32::MAX);
        d(&mut table, 32, 0x80);
        q(&mut table, 40, (7u64 << 48) | 2);
        open.extend_from_slice(&table);
        for (physical, payload) in [(6usize, names), (7, open)] {
            edit(
                &mut raw[physical * PAGE..(physical + 1) * PAGE],
                0xc101,
                |page| {
                    w(page, 24, (112 + payload.len()) as u16);
                    d(page, 88, payload.len() as u32);
                    page[112..112 + payload.len()].copy_from_slice(&payload);
                },
            );
        }
        let context = dirty_native_context(raw, &r);
        let replay = dirty_replay(&context, &r);
        let report = inspect_logfile_native_open_analysis(
            context,
            replay,
            NtfsLogDirtyAnalysisLimits {
                entries: 64,
                lcns: 8,
                work: 64 << 20,
            },
            NtfsLogOpenAnalysisLimits {
                entries: 64,
                entry_bytes: 40,
                name_bytes: 64,
            },
            &r,
        )
        .unwrap();
        if trailing == 0 {
            assert!(
                report.dirty_fields_complete(),
                "{:?}",
                report.stopping_error()
            );
            assert_eq!(
                report.open_attributes().unwrap().initial_names_stop(),
                NtfsLogNameStop::IgnoredTruncatedTail
            );
        } else {
            let error = report.stopping_error().unwrap();
            assert_eq!(error.kind, ErrorKind::Unsupported);
            assert!(error.context.contains("outside declared slots"));
            assert!(!report.dirty_fields_complete());
        }
        assert!(!report.recovery_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn native_private_table_minimum_slot_refusal_preserves_broader_public_generic_decoder() {
    let r = resources();
    let mut raw = native_tables_fixture();
    let mut payload = native_client(31, 0);
    w(&mut payload, 6, 24);
    let mut empty = vec![0; 24];
    w(&mut empty, 0, 32);
    payload.extend_from_slice(&empty);
    edit(&mut raw[5 * PAGE..6 * PAGE], 0xc102, |page| {
        w(page, 24, (112 + payload.len()) as u16);
        d(page, 88, payload.len() as u32);
        page[112..112 + payload.len()].copy_from_slice(&payload);
    });
    let context = dirty_native_context(raw, &r);
    let report = dirty_replay(&context, &r);
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::InvalidData
    );
    assert!(
        report
            .stopping_error()
            .unwrap()
            .context
            .contains("lacks one physical slot")
    );
    assert!(!report.transaction_fields_complete());
    let record = report.dumps().unwrap().dumps()[2].record().unwrap();
    let client = inspect_ntfs_log_client_record(record).unwrap();
    let table = inspect_ntfs_log_restart_table(
        &client,
        NtfsLogRestartTableLimits {
            entries: 32,
            bytes: 8192,
            work: 1 << 20,
        },
        &r,
    )
    .unwrap();
    assert_eq!(table.capacity, 0);
    drop(report);
    drop(context);
    assert_eq!(r.memory.used(), 0);
}

fn target_analysis(reference: u64, named: bool, r: &Resources) -> NtfsLogDirtyAnalysisReport {
    let mut raw = open_suffix_fixture();
    for slot in [2usize, 4] {
        edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xd501, |page| {
            q(page, 176 + 48 + 40 + 16, reference);
            if !named {
                w(page, 176 + 48 + 10, 0);
            }
        });
    }
    target_open_context(dirty_native_context(raw, r), r)
}
fn target_open_context(
    context: NtfsLogNativeAnalysisContext,
    r: &Resources,
) -> NtfsLogDirtyAnalysisReport {
    let replay = dirty_replay(&context, r);
    inspect_logfile_native_open_analysis(
        context,
        replay,
        NtfsLogDirtyAnalysisLimits {
            entries: 64,
            lcns: 8,
            work: 64 << 20,
        },
        NtfsLogOpenAnalysisLimits {
            entries: 64,
            entry_bytes: 40,
            name_bytes: 1024,
        },
        r,
    )
    .unwrap()
}
fn target_limits() -> NtfsLogTargetIntentLimits {
    NtfsLogTargetIntentLimits {
        targets: 8,
        capture: NtfsLogNativeContextLimits {
            reads: 256,
            bytes: 262144,
            work: 1_000_000,
        },
        streams: partmgr::fs_ntfs::NtfsStreamLimits {
            extension_records: 8,
            list_entries: 64,
            list_bytes: 4096,
            attributes: 32,
            runs: 64,
            work: 1_000_000,
        },
        work: 128 << 20,
    }
}
#[test]
fn source_owned_target_queries_distinguish_actual_existing_and_provisional_branches() {
    for (reference, named, expected) in [
        (
            (7u64 << 48) | 2,
            false,
            NtfsLogTargetObservation::ExistingAttributeCandidates,
        ),
        (
            (7u64 << 48) | 2,
            true,
            NtfsLogTargetObservation::ProvisionalMissingAttribute,
        ),
        (
            (8u64 << 48) | 2,
            false,
            NtfsLogTargetObservation::ObservedSequenceConflict,
        ),
        (
            (7u64 << 48) | 16,
            false,
            NtfsLogTargetObservation::ObservedUnusedFile,
        ),
        (
            (7u64 << 48) | (1 << 40),
            false,
            NtfsLogTargetObservation::ObservedOutsideMft,
        ),
    ] {
        let r = resources();
        let analysis = target_analysis(reference, named, &r);
        assert!(
            analysis.dirty_fields_complete(),
            "{:?}",
            analysis.stopping_error()
        );
        let report = inspect_logfile_native_target_intents(analysis, target_limits(), &r).unwrap();
        let unresolved = matches!(
            expected,
            NtfsLogTargetObservation::ObservedOutsideMft
                | NtfsLogTargetObservation::ObservedUnusedFile
                | NtfsLogTargetObservation::ObservedSequenceConflict
        );
        assert_eq!(
            report.target_observations_complete(),
            !unresolved,
            "{:?}",
            report.stopping_error()
        );
        assert_eq!(report.targets().len(), 1);
        let target = &report.targets()[0];
        assert_eq!(target.open_slot_offset(), 24);
        assert_eq!(target.file_reference(), reference);
        assert_eq!(target.observation(), expected);
        if unresolved {
            assert_eq!(
                target.stopping_error().unwrap().kind,
                ErrorKind::Unsupported
            );
            assert!(target.provisional_attribute().is_none());
            assert!(target.owner().is_none());
        } else {
            assert!(target.stopping_error().is_none());
        }
        if expected == NtfsLogTargetObservation::ExistingAttributeCandidates {
            assert!(target.owner().is_some());
            assert_eq!(target.matching_occurrences().len(), 1);
            let winner = target.selected_occurrence().unwrap();
            assert_eq!(target.attributes().unwrap()[winner].kind, 0x80);
            assert_eq!(
                target.native_runs().unwrap(),
                &[NtfsLogNativeRun {
                    vcn: 0,
                    lcn: Some(512),
                    clusters: 512
                }]
            );
            assert!(target.provisional_attribute().is_none());
        } else if !unresolved {
            let fake = target.provisional_attribute().unwrap();
            assert_eq!(&fake[..4], &0x80u32.to_le_bytes());
            assert_eq!(fake[8], 1);
            assert_eq!(fake[9], if named { 4 } else { 0 });
            assert_eq!(&fake[16..24], &[0; 8]);
            assert_eq!(&fake[24..32], &u64::MAX.to_le_bytes());
            assert_eq!(&fake[40..64], &[0; 24]);
            if named {
                assert_eq!(&fake[64..72], &[b'n', 0, b'a', 0, b'm', 0, b'e', 0]);
            }
            if expected != NtfsLogTargetObservation::ProvisionalMissingAttribute {
                assert!(target.owner().is_none());
            }
        }
        assert!(!report.active_window_complete());
        assert!(!report.recovery_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn source_owned_target_capture_refusal_retains_original_error_and_refunds() {
    let r = resources();
    let analysis = target_analysis((7u64 << 48) | 2, false, &r);
    let mut limits = target_limits();
    limits.capture.reads = 0;
    let report = inspect_logfile_native_target_intents(analysis, limits, &r).unwrap();
    assert!(!report.target_observations_complete());
    assert!(report.stopping_error().is_some());
    assert_eq!(report.targets().len(), 1);
    assert_eq!(
        report.targets()[0].observation(),
        NtfsLogTargetObservation::LookupFailed
    );
    assert!(report.targets()[0].provisional_attribute().is_none());
    assert!(report.targets()[0].owner().is_none());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn source_owned_target_enumeration_work_limit_stops_before_target_io() {
    let r = resources();
    let analysis = target_analysis((7u64 << 48) | 2, false, &r);
    let mut limits = target_limits();
    limits.work = analysis.work();
    let report = inspect_logfile_native_target_intents(analysis, limits, &r).unwrap();
    assert!(!report.target_observations_complete());
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert!(report.targets().is_empty());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn source_owned_target_repeats_each_consumed_physical_observation() {
    use std::sync::atomic::AtomicBool;
    struct Ephemeral {
        raw: Image,
        armed: AtomicBool,
        observed: AtomicBool,
    }
    impl ReadAt for Ephemeral {
        fn len(&self) -> u64 {
            self.raw.len()
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            self.raw.read_exact_at(offset, out)?;
            let target = 2048 + 24 * 1024 + 900;
            if self.armed.load(Ordering::SeqCst)
                && offset <= target
                && target < offset + out.len() as u64
                && !self.observed.swap(true, Ordering::SeqCst)
            {
                out[(target - offset) as usize] ^= 1;
            }
            Ok(())
        }
    }
    let r = resources();
    let mut raw = open_suffix_fixture();
    for slot in [2usize, 4] {
        edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xd502, |page| {
            q(page, 176 + 48 + 40 + 16, (7u64 << 48) | 24);
            w(page, 176 + 48 + 10, 0);
        });
    }
    let mut volume = dirty_native_volume(raw);
    use dirty_native_volume_fixture::{name_value, put, resident};
    put(
        &mut volume,
        24,
        &[
            resident(0x10, &[0; 48], 0),
            resident(0x30, &name_value("alpha", 5), 1),
            resident(0x30, &name_value("beta", 5), 2),
            resident(0x80, b"hello", 3),
        ],
        false,
        2,
    );
    let source = Arc::new(Ephemeral {
        raw: Image::new(volume),
        armed: AtomicBool::new(false),
        observed: AtomicBool::new(false),
    });
    let context = dirty_native_context_source(source.clone(), &r);
    let analysis = target_open_context(context, &r);
    assert!(
        analysis.dirty_fields_complete(),
        "{:?}",
        analysis.stopping_error()
    );
    source.armed.store(true, Ordering::SeqCst);
    let report = inspect_logfile_native_target_intents(analysis, target_limits(), &r).unwrap();
    assert!(source.observed.load(Ordering::SeqCst));
    assert!(!report.target_observations_complete());
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::StalePlan);
    assert_eq!(report.targets().len(), 1);
    assert!(report.targets()[0].source_observations() > 0);
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

fn target_log(reference: u64, named: bool) -> Vec<u8> {
    let mut raw = open_suffix_fixture();
    for slot in [2usize, 4] {
        edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xd601, |p| {
            q(p, 176 + 48 + 40 + 16, reference);
            if !named {
                w(p, 176 + 48 + 10, 0);
            }
        });
    }
    raw
}
fn target_list_entry(kind: u32, name: &[u16], number: u64, id: u16) -> Vec<u8> {
    let mut raw = vec![0; (26 + name.len() * 2).next_multiple_of(8)];
    let len = raw.len();
    d(&mut raw, 0, kind);
    w(&mut raw, 4, len as u16);
    raw[6] = name.len() as u8;
    raw[7] = 26;
    q(&mut raw, 16, (7u64 << 48) | number);
    w(&mut raw, 24, id);
    for (i, u) in name.iter().enumerate() {
        w(&mut raw, 26 + i * 2, *u);
    }
    raw
}
#[test]
fn native_named_private_run_keeps_physical_suffix_beyond_logical_eof() {
    use dirty_native_volume_fixture::{name_value, named_allocation, nonresident, put, resident};
    let r = resources();
    let mut volume = dirty_native_volume(target_log((7u64 << 48) | 24, true));
    let ads = named_allocation(
        nonresident(&[0x11, 3, 70, 0], 3, 100, 100, false),
        0x80,
        "name",
        9,
    );
    put(
        &mut volume,
        24,
        &[
            resident(0x10, &[0; 48], 0),
            resident(0x30, &name_value("alpha", 5), 1),
            resident(0x80, b"hello", 3),
            ads,
        ],
        false,
        1,
    );
    let context = dirty_native_context_source(Arc::new(Image::new(volume)), &r);
    let analysis = target_open_context(context, &r);
    let report = inspect_logfile_native_target_intents(analysis, target_limits(), &r).unwrap();
    assert!(
        report.target_observations_complete(),
        "{:?}",
        report.stopping_error()
    );
    let target = &report.targets()[0];
    let winner = target.selected_occurrence().unwrap();
    assert_eq!(target.attributes().unwrap()[winner].instance, 9);
    assert_eq!(
        target.native_runs().unwrap(),
        &[NtfsLogNativeRun {
            vcn: 0,
            lcn: Some(70),
            clusters: 3
        }]
    );
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn native_list_winner_uses_source_upcase_early_stop_without_sorting_candidates() {
    use dirty_native_volume_fixture::{name_value, named_allocation, nonresident, put, resident};
    for ordered in [true, false] {
        let r = resources();
        let mut volume = dirty_native_volume(target_log((7u64 << 48) | 24, true));
        let mut list = target_list_entry(0x10, &[], 24, 0);
        list.extend(target_list_entry(0x30, &[], 24, 1));
        list.extend(target_list_entry(0x80, &[], 24, 3));
        let name = [b'n' as u16, b'a' as u16, b'm' as u16, b'e' as u16];
        let other = [b'Z' as u16, b'x' as u16, b'x' as u16, b'x' as u16];
        if ordered {
            list.extend(target_list_entry(0x80, &name, 24, 9));
            list.extend(target_list_entry(0x80, &other, 24, 10));
        } else {
            list.extend(target_list_entry(0x80, &other, 24, 10));
            list.extend(target_list_entry(0x80, &name, 24, 9));
        }
        let ads = named_allocation(
            nonresident(&[0x11, 3, 70, 0], 3, 100, 100, false),
            0x80,
            "name",
            9,
        );
        let other = named_allocation(
            nonresident(&[0x11, 1, 80, 0], 1, 100, 100, false),
            0x80,
            "Zxxx",
            10,
        );
        put(
            &mut volume,
            24,
            &[
                resident(0x10, &[0; 48], 0),
                resident(0x20, &list, 4),
                resident(0x30, &name_value("alpha", 5), 1),
                resident(0x80, b"hello", 3),
                other,
                ads,
            ],
            false,
            1,
        );
        let context = dirty_native_context_source(Arc::new(Image::new(volume)), &r);
        let analysis = target_open_context(context, &r);
        let report = inspect_logfile_native_target_intents(analysis, target_limits(), &r).unwrap();
        assert!(
            report.target_observations_complete(),
            "{:?}",
            report.stopping_error()
        );
        let target = &report.targets()[0];
        assert_eq!(target.matching_occurrences().len(), 1);
        if ordered {
            let winner = target.selected_occurrence().unwrap();
            assert_eq!(target.attributes().unwrap()[winner].instance, 9);
            assert_eq!(
                target.native_runs().unwrap(),
                &[NtfsLogNativeRun {
                    vcn: 0,
                    lcn: Some(70),
                    clusters: 3
                }]
            );
        } else {
            assert_eq!(
                target.observation(),
                NtfsLogTargetObservation::ProvisionalNativeSelectionMiss
            );
            assert!(target.selected_occurrence().is_none());
            assert!(target.provisional_attribute().is_some());
            assert!(target.native_runs().unwrap().is_empty());
        }
        assert!(target.source_observations() > 0);
        assert!(!report.active_window_complete());
        assert!(!report.recovery_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn native_dirty_target_runs_preserve_source_and_provisional_identity() {
    for named in [false, true] {
        let r = resources();
        let analysis = target_analysis((7u64 << 48) | 2, named, &r);
        let input = inspect_logfile_native_target_intents(analysis, target_limits(), &r).unwrap();
        let report = inspect_logfile_native_dirty_runs(
            input,
            NtfsLogDirtyRunLimits {
                targets: 8,
                runs: 128,
                work: 256 << 20,
            },
            &r,
        )
        .unwrap();
        assert!(
            report.dirty_runs_complete(),
            "{:?}",
            report.stopping_error()
        );
        assert_eq!(report.targets().len(), report.input().targets().len());
        assert_eq!(report.redo_lsn(), Some(lsn(4 * PAGE + 176)));
        for derived in report.targets() {
            let original = report
                .input()
                .targets()
                .iter()
                .find(|t| t.open_slot_offset() == derived.open_slot_offset())
                .unwrap();
            if named {
                assert!(original.selected_occurrence().is_none());
                assert!(original.provisional_attribute().is_some());
                assert_eq!(
                    u64::from_le_bytes(
                        original.provisional_attribute().unwrap()[24..32]
                            .try_into()
                            .unwrap()
                    ),
                    u64::MAX
                );
            } else {
                assert!(original.selected_occurrence().is_some());
            }
            if named {
                assert_eq!(
                    derived.runs(),
                    &[NtfsLogNativeRun {
                        vcn: 0,
                        lcn: Some(100),
                        clusters: 1
                    }]
                );
                assert_eq!(derived.nonresident_sizes(), Some([512; 3]));
            } else {
                assert_eq!(
                    derived.runs(),
                    &[
                        NtfsLogNativeRun {
                            vcn: 0,
                            lcn: Some(100),
                            clusters: 1
                        },
                        NtfsLogNativeRun {
                            vcn: 1,
                            lcn: Some(513),
                            clusters: 511
                        }
                    ]
                );
                assert_eq!(derived.nonresident_sizes(), Some([262144; 3]));
                assert_eq!(
                    original.native_runs().unwrap(),
                    &[NtfsLogNativeRun {
                        vcn: 0,
                        lcn: Some(512),
                        clusters: 512
                    }]
                );
            }
        }
        assert!(!report.active_window_complete());
        assert!(!report.recovery_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn native_dirty_run_ceiling_retains_original_inputs_and_refunds() {
    let r = resources();
    let input = inspect_logfile_native_target_intents(
        target_analysis((7u64 << 48) | 2, false, &r),
        target_limits(),
        &r,
    )
    .unwrap();
    let report = inspect_logfile_native_dirty_runs(
        input,
        NtfsLogDirtyRunLimits {
            targets: 8,
            runs: 1,
            work: 256 << 20,
        },
        &r,
    )
    .unwrap();
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert!(!report.dirty_runs_complete());
    assert_eq!(
        report.input().targets()[0].native_runs().unwrap()[0].clusters,
        512
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

fn dirty_shared_open_fixture(named: bool) -> Vec<u8> {
    let mut raw = checkpoint_fixture(0, lsn(4 * PAGE + 64));
    let starts = [176usize, 312, 448];
    let current = lsn(4 * PAGE + 448);
    for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
        edit(restart, 0xd801, |page| {
            q(page, 56, current);
            d(page, 88, 40);
        });
    }
    for slot in [2usize, 4] {
        let mut page = framed(1, slot == 4, 4 * PAGE, current, 1, 1);
        edit(&mut page, 0xd802, |page| {
            w(page, 24, 536);
            q(page, 64, lsn(4 * PAGE + 64));
            d(page, 88, 64);
            d(page, 96, 2);
            d(page, 112, 1);
            for (i, start) in starts.iter().copied().enumerate() {
                let mut payload = native_client(if i < 2 { 28 } else { 8 }, 0);
                w(&mut payload, 12, if i == 0 { 24 } else { 64 });
                if i < 2 {
                    let mut entry = [0; 40];
                    d(&mut entry, 0, u32::MAX);
                    d(&mut entry, 8, 0x80);
                    q(&mut entry, 16, (7u64 << 48) | 2);
                    q(&mut entry, 24, lsn(4 * PAGE + start));
                    payload.extend_from_slice(&entry);
                    payload.extend_from_slice(&[b'n', 0, b'a', 0, b'm', 0, b'e', 0]);
                    w(&mut payload, 6, 40);
                    w(&mut payload, 8, 80);
                    w(&mut payload, 10, if named { 8 } else { 0 });
                } else {
                    w(&mut payload, 14, 1);
                    q(&mut payload, 32, 100);
                }
                q(page, start, lsn(4 * PAGE + start));
                q(
                    page,
                    start + 8,
                    if i == 0 {
                        0
                    } else {
                        lsn(4 * PAGE + starts[i - 1])
                    },
                );
                d(page, start + 24, payload.len() as u32);
                w(page, start + 28, 9);
                d(page, start + 32, 1);
                d(page, start + 36, 24);
                page[start + 48..start + 48 + payload.len()].copy_from_slice(&payload);
            }
        });
        install(&mut raw, slot, &page);
    }
    raw
}
#[test]
fn native_dirty_existing_shared_cache_and_fake_private_maps_are_distinct() {
    for named in [false, true] {
        let r = resources();
        let analysis = target_open_context(
            dirty_native_context(dirty_shared_open_fixture(named), &r),
            &r,
        );
        assert!(
            analysis.dirty_fields_complete(),
            "{:?}",
            analysis.stopping_error()
        );
        let input = inspect_logfile_native_target_intents(analysis, target_limits(), &r).unwrap();
        let report = inspect_logfile_native_dirty_runs(
            input,
            NtfsLogDirtyRunLimits {
                targets: 8,
                runs: 128,
                work: 256 << 20,
            },
            &r,
        )
        .unwrap();
        assert!(
            report.dirty_runs_complete(),
            "{:?}",
            report.stopping_error()
        );
        assert_eq!(report.targets().len(), 2);
        assert_eq!(report.targets()[0].open_slot_offset(), 24);
        assert_eq!(report.targets()[1].open_slot_offset(), 64);
        if named {
            assert!(report.targets()[0].runs().is_empty());
            assert_eq!(report.targets()[0].nonresident_sizes(), Some([0; 3]));
            assert_eq!(
                report.targets()[1].runs(),
                &[NtfsLogNativeRun {
                    vcn: 0,
                    lcn: Some(100),
                    clusters: 1
                }]
            );
            assert_eq!(report.targets()[1].nonresident_sizes(), Some([512; 3]));
        } else {
            assert_eq!(report.targets()[0].runs(), report.targets()[1].runs());
            assert_eq!(
                report.targets()[0].runs()[0],
                NtfsLogNativeRun {
                    vcn: 0,
                    lcn: Some(100),
                    clusters: 1
                }
            );
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn native_dirty_identical_lcn_does_not_require_split_capacity() {
    let r = resources();
    let mut raw = open_suffix_fixture();
    for slot in [2usize, 4] {
        edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xd901, |page| {
            w(page, 176 + 48 + 10, 0);
            q(page, 312 + 48 + 32, 512);
        });
    }
    let analysis = target_open_context(dirty_native_context(raw, &r), &r);
    let input = inspect_logfile_native_target_intents(analysis, target_limits(), &r).unwrap();
    let report = inspect_logfile_native_dirty_runs(
        input,
        NtfsLogDirtyRunLimits {
            targets: 8,
            runs: 1,
            work: 256 << 20,
        },
        &r,
    )
    .unwrap();
    assert!(
        report.dirty_runs_complete(),
        "{:?}",
        report.stopping_error()
    );
    assert_eq!(
        report.targets()[0].runs(),
        &[NtfsLogNativeRun {
            vcn: 0,
            lcn: Some(512),
            clusters: 512
        }]
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

fn redo_byte_effect_input(r: &Resources) -> NtfsLogDirtyRunReport {
    redo_byte_effect_input_with(|_| {}, r)
}
fn redo_byte_effect_input_with(
    change: impl FnOnce(&mut Vec<u8>),
    r: &Resources,
) -> NtfsLogDirtyRunReport {
    redo_byte_effect_input_source(change, |raw| Arc::new(Image::new(raw)), r)
}
fn redo_byte_effect_input_source(
    change: impl FnOnce(&mut Vec<u8>),
    source: impl FnOnce(Vec<u8>) -> Arc<dyn ReadAt>,
    r: &Resources,
) -> NtfsLogDirtyRunReport {
    let mut raw = open_suffix_fixture();
    let current = lsn(4 * PAGE + 408);
    for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
        edit(restart, 0xda01, |page| q(page, 56, current));
    }
    for slot in [2usize, 4] {
        edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xda02, |page| {
            let noop = page[400..488].to_vec();
            page[408..496].copy_from_slice(&noop);
            page[400..408].copy_from_slice(b"ABCDEFGH");
            w(page, 24, 496);
            if slot == 4 {
                q(page, 8, current);
            }
            q(page, 32, current);
            w(page, 176 + 48 + 10, 0);
            d(page, 312 + 24, 48);
            w(page, 312 + 48 + 6, 8);
            q(page, 408, current);
        });
    }
    change(&mut raw);
    let analysis = target_open_context(
        dirty_native_context_source(source(dirty_native_volume(raw)), r),
        r,
    );
    let input = inspect_logfile_native_target_intents(analysis, target_limits(), r).unwrap();
    inspect_logfile_native_dirty_runs(
        input,
        NtfsLogDirtyRunLimits {
            targets: 8,
            runs: 128,
            work: 256 << 20,
        },
        r,
    )
    .unwrap()
}
fn redo_limits() -> NtfsLogRedoLimits {
    NtfsLogRedoLimits {
        traversal: physical_limits(),
        capture: NtfsLogNativeContextLimits {
            reads: 1024,
            bytes: 524288,
            work: 2 << 20,
        },
        fragments: 16,
        bytes: 8192,
        runtime_bytes: 8192,
        runtime_runs: 256,
        files: 8,
        file_bytes: 8192,
        work: 512 << 20,
    }
}
#[test]
fn native_redo_exact_seed_and_actual_nonresident_shadow_bytes() {
    let r = resources();
    let input = redo_byte_effect_input(&r);
    assert!(input.dirty_runs_complete(), "{:?}", input.stopping_error());
    let seed = input.redo_lsn().unwrap();
    let report = inspect_logfile_native_redo(input, redo_limits(), &r).unwrap();
    assert!(
        report.admitted_redo_complete(),
        "{:?}",
        report.stopping_error()
    );
    assert_eq!(seed, lsn(4 * PAGE + 176));
    assert_eq!(
        report.traversal().unwrap().steps()[0]
            .record()
            .header()
            .unwrap()
            .this_lsn,
        seed
    );
    assert_eq!(report.processed_records(), 3);
    assert_eq!(report.fragments().len(), 1);
    assert_eq!(report.fragments()[0].lsn(), lsn(4 * PAGE + 312));
    assert_eq!(report.fragments()[0].offset(), 100 * 512);
    assert_eq!(report.fragments()[0].after(), b"ABCDEFGH");
    assert_ne!(
        report.fragments()[0].original(),
        report.fragments()[0].after()
    );
    assert!(!report.active_window_complete());
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn native_redo_fragment_ceiling_retains_exact_queries_and_original_cause() {
    let r = resources();
    let input = redo_byte_effect_input(&r);
    let mut limits = redo_limits();
    limits.fragments = 0;
    let report = inspect_logfile_native_redo(input, limits, &r).unwrap();
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert!(!report.admitted_redo_complete());
    assert!(report.traversal().is_some());
    assert!(report.fragments().is_empty());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_runtime_bitmap_source_mask_and_dirty_volume_decision() {
    for (operation, offset, bits) in [(21u16, 3u32, 10u32), (22, 3, 10), (21, 4096, 1)] {
        let r = resources();
        let input = redo_byte_effect_input_with(
            |raw| {
                for slot in [2usize, 4] {
                    edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xdb01, |page| {
                        w(page, 312 + 48, operation);
                        d(page, 400, offset);
                        d(page, 404, bits);
                    });
                }
            },
            &r,
        );
        let report = inspect_logfile_native_redo(input, redo_limits(), &r).unwrap();
        assert!(
            report.admitted_redo_complete(),
            "{:?}",
            report.stopping_error()
        );
        assert_eq!(report.runtime_targets().len(), 1);
        assert_eq!(report.runtime_targets()[0].open_slot_offset(), 24);
        assert!(!report.runtime_targets()[0].private_run0());
        assert_eq!(report.fragments().len(), 1);
        let fragment = &report.fragments()[0];
        assert_eq!(fragment.original().len(), 512);
        if offset == 4096 {
            assert!(report.dirty_volume_observed());
            assert!(!fragment.is_write());
            assert_eq!(fragment.original(), fragment.after());
        } else {
            assert!(!report.dirty_volume_observed());
            assert!(fragment.is_write());
            let mut expected = fragment.original().to_vec();
            for bit in offset..offset + bits {
                let mask = 1u8 << (bit % 8);
                if operation == 21 {
                    expected[bit as usize / 8] |= mask;
                } else {
                    expected[bit as usize / 8] &= !mask;
                }
            }
            assert_eq!(fragment.after(), expected);
        }
        assert!(!report.recovery_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn native_runtime_successful_read_survives_post_read_cancellation() {
    struct CancelRead {
        raw: Image,
        armed: Arc<std::sync::atomic::AtomicBool>,
        cancellation: Cancellation,
    }
    impl ReadAt for CancelRead {
        fn len(&self) -> u64 {
            self.raw.len()
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            self.raw.read_exact_at(offset, out)?;
            if offset == 100 * 512 && self.armed.load(Ordering::SeqCst) {
                self.cancellation.cancel();
            }
            Ok(())
        }
    }
    let r = resources();
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let input = redo_byte_effect_input_source(
        |_| {},
        |raw| {
            Arc::new(CancelRead {
                raw: Image::new(raw),
                armed: armed.clone(),
                cancellation: r.cancellation.clone(),
            })
        },
        &r,
    );
    armed.store(true, Ordering::SeqCst);
    let report = inspect_logfile_native_redo(input, redo_limits(), &r).unwrap();
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::Cancelled);
    assert_eq!(report.fragments().len(), 1);
    let read = &report.fragments()[0];
    assert_eq!(read.offset(), 100 * 512);
    assert_eq!(read.original().len(), 8);
    assert_eq!(read.original(), read.after());
    assert!(!read.is_write());
    assert!(!report.admitted_redo_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_runtime_first_retained_read_survives_exact_work_refusal() {
    let r = resources();
    let full = inspect_logfile_native_redo(redo_byte_effect_input(&r), redo_limits(), &r).unwrap();
    assert!(full.admitted_redo_complete());
    let mut high = full.work();
    drop(full);
    let mut low = 0;
    while low < high {
        let middle = low + (high - low) / 2;
        let mut limits = redo_limits();
        limits.work = middle;
        let report = inspect_logfile_native_redo(redo_byte_effect_input(&r), limits, &r).unwrap();
        if report.fragments().is_empty() {
            low = middle + 1;
        } else {
            high = middle;
        }
        drop(report);
    }
    let mut limits = redo_limits();
    limits.work = low;
    let report = inspect_logfile_native_redo(redo_byte_effect_input(&r), limits, &r).unwrap();
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(report.fragments().len(), 1);
    assert_eq!(
        report.fragments()[0].original(),
        report.fragments()[0].after()
    );
    assert!(!report.fragments()[0].is_write());
    drop(report);
    assert!(low > 0);
    limits.work = low - 1;
    let below = inspect_logfile_native_redo(redo_byte_effect_input(&r), limits, &r).unwrap();
    assert_eq!(
        below.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert!(below.fragments().is_empty());
    drop(below);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_file_deallocation_reuses_source_loaded_cache_and_mft_mapping() {
    let r = resources();
    let input = redo_byte_effect_input_source(
        |raw| {
            let current = lsn(4 * PAGE + 504);
            for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
                edit(restart, 0xe201, |page| q(page, 56, current));
            }
            for slot in [2usize, 4] {
                edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xe202, |page| {
                    let noop = page[408..496].to_vec();
                    let action = page[312..400].to_vec();
                    page[504..592].copy_from_slice(&noop);
                    page[408..496].copy_from_slice(&action);
                    page[496..504].copy_from_slice(b"ignored!");
                    w(page, 24, 592);
                    if slot == 4 {
                        q(page, 8, current);
                    }
                    q(page, 32, current);
                    // Keep the source-owned FILE24, but select its genuinely
                    // absent named DATA via the existing UTF16 name payload.
                    w(page, 176 + 48 + 10, 8);
                    q(page, 176 + 48 + 40 + 16, (7u64 << 48) | 24);
                    for start in [312usize, 408] {
                        q(page, start, lsn(4 * PAGE + start));
                        w(page, start + 48, 3);
                        q(page, start + 48 + 24, 48);
                    }
                    q(page, 504, current);
                });
            }
        },
        |mut volume| {
            use dirty_native_volume_fixture::{name_value, put, resident};
            // Native ni admission requires STANDARD_INFORMATION; the shared
            // audit-only seed intentionally does not provide it for FILE24.
            put(
                &mut volume,
                24,
                &[
                    resident(0x10, &[0; 48], 0),
                    resident(0x30, &name_value("alpha", 5), 1),
                    resident(0x30, &name_value("beta", 5), 2),
                    resident(0x80, b"hello", 3),
                ],
                false,
                2,
            );
            // Native pre-replay mount loads $MFTMirr with sequence1 and SI.
            put(
                &mut volume,
                1,
                &[
                    resident(0x10, &[0; 48], 0),
                    resident(0x30, &name_value("$MFTMirr", 5), 2),
                    dirty_native_volume_fixture::nonresident(
                        &[0x21, 8, 0xf4, 1, 0],
                        8,
                        4096,
                        4096,
                        false,
                    ),
                ],
                false,
                1,
            );
            w(&mut volume, 2048 + 1024 + 16, 1);
            let mirror = volume[2048..6144].to_vec();
            volume[500 * 512..508 * 512].copy_from_slice(&mirror);
            Arc::new(Image::new(volume))
        },
        &r,
    );
    assert!(input.dirty_runs_complete(), "{:?}", input.stopping_error());
    let report = inspect_logfile_native_redo(input, redo_limits(), &r).unwrap();
    assert!(
        report.admitted_redo_complete(),
        "{:?}",
        report.stopping_error()
    );
    assert_eq!(report.runtime_files().len(), 1);
    let file = &report.runtime_files()[0];
    assert_eq!(file.number(), 24);
    assert!(file.cached());
    assert!(file.loaded());
    assert_eq!(
        u16::from_le_bytes(file.bytes()[16..18].try_into().unwrap()),
        9
    );
    assert_eq!(
        u16::from_le_bytes(file.bytes()[22..24].try_into().unwrap()) & 1,
        0
    );
    assert_eq!(report.fragments().len(), 3);
    assert!(!report.fragments()[0].is_write());
    assert!(
        report.fragments()[1..]
            .iter()
            .all(|fragment| fragment.is_write())
    );
    assert!(
        report
            .fragments()
            .iter()
            .all(|fragment| fragment.offset() == 2048 + 24 * 1024)
    );
    assert_eq!(
        u64::from_le_bytes(file.bytes()[8..16].try_into().unwrap()),
        lsn(4 * PAGE + 408)
    );
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

fn undo_limits() -> NtfsLogUndoLimits {
    let traversal = physical_limits();
    // The fixture has one contiguous $LogFile DATA extent. An exact query
    // reads the two restart copies and at most record.pages physical pages;
    // each page translates to one physical source read. Keep the capture
    // inventory proportional to that actual query, rather than reserving
    // 1024 Guard entries separately for every retained undo record.
    let reads = 2 + traversal.record.pages;
    NtfsLogUndoLimits {
        transactions: 64,
        traversal,
        capture: NtfsLogNativeContextLimits {
            reads,
            bytes: reads * PAGE,
            work: 2 << 20,
        },
        work: 768 << 20,
    }
}
#[test]
fn native_undo_follows_exact_foreign_and_type2_links_without_next_client_filter() {
    let r = resources();
    let input = redo_byte_effect_input_with(
        |raw| {
            let current = lsn(4 * PAGE + 672);
            for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
                edit(restart, 0xe301, |page| q(page, 56, current));
            }
            for slot in [2usize, 4] {
                edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xe302, |page| {
                    let noop = page[408..496].to_vec();
                    for start in [496usize, 584, 672] {
                        page[start..start + 88].copy_from_slice(&noop);
                        q(page, start, lsn(4 * PAGE + start));
                        q(page, start + 8, 0);
                        q(page, start + 16, 0);
                    }
                    // Native undo follows these exact links rather than increasing
                    // physical order, selected-client filtering or LFS type1 filtering.
                    q(page, 672 + 16, lsn(4 * PAGE + 496));
                    q(page, 496 + 16, lsn(4 * PAGE + 584));
                    w(page, 496 + 28, 10);
                    d(page, 584 + 32, 2);
                    w(page, 24, 760);
                    q(page, 32, current);
                    if slot == 4 {
                        q(page, 8, current);
                    }
                });
            }
        },
        &r,
    );
    assert!(input.dirty_runs_complete(), "{:?}", input.stopping_error());
    let redo = inspect_logfile_native_redo(input, redo_limits(), &r).unwrap();
    assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
    let report = inspect_logfile_native_undo(redo, undo_limits(), &r).unwrap();
    assert!(
        report.admitted_undo_complete(),
        "{:?}",
        report.stopping_error()
    );
    assert_eq!(
        report
            .steps()
            .iter()
            .map(|s| s.requested_lsn())
            .collect::<Vec<_>>(),
        [
            lsn(4 * PAGE + 672),
            lsn(4 * PAGE + 496),
            lsn(4 * PAGE + 584)
        ]
    );
    assert_eq!(
        report.steps()[1]
            .record()
            .unwrap()
            .header()
            .unwrap()
            .client_sequence,
        10
    );
    assert_eq!(
        report.steps()[2]
            .record()
            .unwrap()
            .header()
            .unwrap()
            .record_type,
        2
    );
    assert!(
        report
            .steps()
            .iter()
            .all(|step| step.disposition() == NtfsLogUndoDisposition::Noop)
    );
    assert!(report.transactions().iter().all(|t| t.released()));
    assert!(!report.active_window_complete());
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_undo_retains_unsupported_dispatch_without_releasing_transaction() {
    let r = resources();
    let input = redo_byte_effect_input_with(
        |raw| {
            let current = lsn(4 * PAGE + 672);
            for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
                edit(restart, 0xe301, |page| q(page, 56, current));
            }
            for slot in [2usize, 4] {
                edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xe302, |page| {
                    let noop = page[408..496].to_vec();
                    for start in [496usize, 584, 672] {
                        page[start..start + 88].copy_from_slice(&noop);
                        q(page, start, lsn(4 * PAGE + start));
                        q(page, start + 8, 0);
                        q(page, start + 16, 0);
                    }
                    // Native undo follows these exact links rather than increasing
                    // physical order, selected-client filtering or LFS type1 filtering.
                    q(page, 672 + 16, lsn(4 * PAGE + 496));
                    q(page, 496 + 16, lsn(4 * PAGE + 584));
                    w(page, 496 + 28, 10);
                    d(page, 584 + 32, 2);
                    w(page, 672 + 48 + 2, 9);
                    w(page, 672 + 48 + 12, 24);
                    w(page, 24, 760);
                    q(page, 32, current);
                    if slot == 4 {
                        q(page, 8, current);
                    }
                });
            }
        },
        &r,
    );
    assert!(input.dirty_runs_complete(), "{:?}", input.stopping_error());
    let redo = inspect_logfile_native_redo(input, redo_limits(), &r).unwrap();
    assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
    let report = inspect_logfile_native_undo(redo, undo_limits(), &r).unwrap();
    assert!(!report.admitted_undo_complete());
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::Unsupported
    );
    assert_eq!(report.steps().len(), 1);
    assert_eq!(
        report.steps()[0].disposition(),
        NtfsLogUndoDisposition::UnsupportedOperation(9)
    );
    assert!(report.steps()[0].record().unwrap().complete());
    assert!(
        report
            .transactions()
            .iter()
            .any(|transaction| transaction.active() && !transaction.released())
    );
    assert!(!report.active_window_complete());
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_undo_nonnoop_skip_reaches_release_after_target_preparation() {
    let r = resources();
    let input = redo_byte_effect_input_with(
        |raw| {
            let current = lsn(4 * PAGE + 672);
            for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
                edit(restart, 0xe301, |page| q(page, 56, current));
            }
            for slot in [2usize, 4] {
                edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xe302, |page| {
                    let noop = page[408..496].to_vec();
                    for start in [496usize, 584, 672] {
                        page[start..start + 88].copy_from_slice(&noop);
                        q(page, start, lsn(4 * PAGE + start));
                        q(page, start + 8, 0);
                        q(page, start + 16, 0);
                    }
                    // Native undo follows these exact links rather than increasing
                    // physical order, selected-client filtering or LFS type1 filtering.
                    q(page, 672 + 16, lsn(4 * PAGE + 496));
                    q(page, 496 + 16, lsn(4 * PAGE + 584));
                    w(page, 496 + 28, 10);
                    d(page, 584 + 32, 2);
                    w(page, 672 + 48 + 2, 10);
                    w(page, 672 + 48 + 12, 24);
                    w(page, 24, 760);
                    q(page, 32, current);
                    if slot == 4 {
                        q(page, 8, current);
                    }
                });
            }
        },
        &r,
    );
    assert!(input.dirty_runs_complete(), "{:?}", input.stopping_error());
    let redo = inspect_logfile_native_redo(input, redo_limits(), &r).unwrap();
    assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
    let report = inspect_logfile_native_undo(redo, undo_limits(), &r).unwrap();
    assert!(
        report.admitted_undo_complete(),
        "{:?}",
        report.stopping_error()
    );
    assert_eq!(report.steps().len(), 3);
    assert_eq!(
        report.steps()[0].disposition(),
        NtfsLogUndoDisposition::SkippedOperation(10)
    );
    assert!(
        report
            .transactions()
            .iter()
            .all(|transaction| transaction.released())
    );
    assert!(!report.active_window_complete());
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_undo_deallocation_reuses_shared_file_effect_with_null_redo_lsn() {
    let r = resources();
    let input = redo_byte_effect_input_source(
        |raw| {
            let current = lsn(4 * PAGE + 504);
            for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
                edit(restart, 0xe201, |page| q(page, 56, current));
            }
            for slot in [2usize, 4] {
                edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xe202, |page| {
                    let noop = page[408..496].to_vec();
                    let action = page[312..400].to_vec();
                    page[504..592].copy_from_slice(&noop);
                    page[408..496].copy_from_slice(&action);
                    page[496..504].copy_from_slice(b"ignored!");
                    w(page, 24, 592);
                    if slot == 4 {
                        q(page, 8, current);
                    }
                    q(page, 32, current);
                    // Keep the source-owned FILE24, but select its genuinely
                    // absent named DATA via the existing UTF16 name payload.
                    w(page, 176 + 48 + 10, 8);
                    q(page, 176 + 48 + 40 + 16, (7u64 << 48) | 24);
                    for start in [312usize, 408] {
                        q(page, start, lsn(4 * PAGE + start));
                        w(page, start + 48, 3);
                        q(page, start + 48 + 24, 48);
                    }
                    q(page, 504, current);
                    q(page, 504 + 16, lsn(4 * PAGE + 408));
                    q(page, 408 + 16, 0);
                    w(page, 408 + 48 + 2, 3);
                });
            }
        },
        |mut volume| {
            use dirty_native_volume_fixture::{name_value, put, resident};
            // Native ni admission requires STANDARD_INFORMATION; the shared
            // audit-only seed intentionally does not provide it for FILE24.
            put(
                &mut volume,
                24,
                &[
                    resident(0x10, &[0; 48], 0),
                    resident(0x30, &name_value("alpha", 5), 1),
                    resident(0x30, &name_value("beta", 5), 2),
                    resident(0x80, b"hello", 3),
                ],
                false,
                2,
            );
            // Native pre-replay mount loads $MFTMirr with sequence1 and SI.
            put(
                &mut volume,
                1,
                &[
                    resident(0x10, &[0; 48], 0),
                    resident(0x30, &name_value("$MFTMirr", 5), 2),
                    dirty_native_volume_fixture::nonresident(
                        &[0x21, 8, 0xf4, 1, 0],
                        8,
                        4096,
                        4096,
                        false,
                    ),
                ],
                false,
                1,
            );
            w(&mut volume, 2048 + 1024 + 16, 1);
            let mirror = volume[2048..6144].to_vec();
            volume[500 * 512..508 * 512].copy_from_slice(&mirror);
            Arc::new(Image::new(volume))
        },
        &r,
    );
    assert!(input.dirty_runs_complete(), "{:?}", input.stopping_error());
    let redo = inspect_logfile_native_redo(input, redo_limits(), &r).unwrap();
    assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
    let report = inspect_logfile_native_undo(redo, undo_limits(), &r).unwrap();
    assert!(
        report.admitted_undo_complete(),
        "{:?}",
        report.stopping_error()
    );
    assert!(
        report
            .steps()
            .iter()
            .any(|step| step.disposition() == NtfsLogUndoDisposition::AppliedOperation(3))
    );
    let file = &report.redo().runtime_files()[0];
    assert_eq!(
        u16::from_le_bytes(file.bytes()[16..18].try_into().unwrap()),
        10
    );
    // NULL redo-LSN leaves the successful preceding redo LSN in the cache.
    assert_eq!(
        u64::from_le_bytes(file.bytes()[8..16].try_into().unwrap()),
        lsn(4 * PAGE + 408)
    );
    assert!(
        report
            .transactions()
            .iter()
            .all(|transaction| transaction.released())
    );
    assert!(!report.active_window_complete());
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_undo_skip_extends_header_before_native_skip_dispatch() {
    let r = resources();
    let input = redo_byte_effect_input_with(
        |raw| {
            let current = lsn(4 * PAGE + 672);
            for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
                edit(restart, 0xe301, |page| q(page, 56, current));
            }
            for slot in [2usize, 4] {
                edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xe302, |page| {
                    let noop = page[408..496].to_vec();
                    for start in [496usize, 584, 672] {
                        page[start..start + 88].copy_from_slice(&noop);
                        q(page, start, lsn(4 * PAGE + start));
                        q(page, start + 8, 0);
                        q(page, start + 16, 0);
                    }
                    // Native undo follows these exact links rather than increasing
                    // physical order, selected-client filtering or LFS type1 filtering.
                    q(page, 672 + 16, lsn(4 * PAGE + 496));
                    q(page, 496 + 16, lsn(4 * PAGE + 584));
                    w(page, 496 + 28, 10);
                    d(page, 584 + 32, 2);
                    w(page, 672 + 48 + 2, 10);
                    w(page, 672 + 48 + 12, 24);
                    w(page, 672 + 48 + 14, 1);
                    q(page, 672 + 48 + 24, 600);
                    w(page, 24, 760);
                    q(page, 32, current);
                    if slot == 4 {
                        q(page, 8, current);
                    }
                });
            }
        },
        &r,
    );
    assert!(input.dirty_runs_complete(), "{:?}", input.stopping_error());
    let redo = inspect_logfile_native_redo(input, redo_limits(), &r).unwrap();
    assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
    // The source-owned unnamed DATA size is LENGTH=262144. Native undo
    // grows only when (target_vcn+1)*cluster exceeds current data_size;
    // VCN600 exercises growth rather than incorrectly expecting shrinkage.
    let before = redo
        .runtime_targets()
        .iter()
        .find(|target| target.open_slot_offset() == 24)
        .unwrap()
        .attribute_bytes();
    assert_eq!(
        u64::from_le_bytes(before[48..56].try_into().unwrap()),
        LENGTH as u64
    );
    let report = inspect_logfile_native_undo(redo, undo_limits(), &r).unwrap();
    assert!(
        report.admitted_undo_complete(),
        "{:?}",
        report.stopping_error()
    );
    assert_eq!(
        report.steps()[0].disposition(),
        NtfsLogUndoDisposition::SkippedOperation(10)
    );
    let raw = report
        .redo()
        .runtime_targets()
        .iter()
        .find(|target| target.open_slot_offset() == 24)
        .unwrap()
        .attribute_bytes();
    assert_ne!(raw[8], 0);
    for offset in [40usize, 48, 56] {
        assert_eq!(
            u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap()),
            601 * 512
        );
    }
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_undo_shares_nonresident_and_bitmap_shadow_effects() {
    for operation in [8u16, 21, 22] {
        let r = resources();
        let input = redo_byte_effect_input_with(
            |raw| {
                for slot in [2usize, 4] {
                    edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xe401, |page| {
                        w(page, 24, 504);
                        d(page, 408 + 24, 48);
                        q(page, 408 + 16, 0);
                        w(page, 408 + 48 + 2, operation);
                        w(page, 408 + 48 + 8, 40);
                        w(page, 408 + 48 + 10, 8);
                        w(page, 408 + 48 + 12, 24);
                        w(page, 408 + 48 + 14, 1);
                        q(page, 408 + 48 + 24, 0);
                        q(page, 408 + 48 + 32, 100);
                        if operation == 8 {
                            page[496..504].copy_from_slice(b"UNDO1234");
                        } else {
                            d(page, 496, 3);
                            d(page, 500, 10);
                        }
                    });
                }
            },
            &r,
        );
        assert!(input.dirty_runs_complete(), "{:?}", input.stopping_error());
        let redo = inspect_logfile_native_redo(input, redo_limits(), &r).unwrap();
        assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
        let report = inspect_logfile_native_undo(redo, undo_limits(), &r).unwrap();
        assert!(
            report.admitted_undo_complete(),
            "{:?}",
            report.stopping_error()
        );
        assert_eq!(
            report.steps()[0].disposition(),
            NtfsLogUndoDisposition::AppliedOperation(operation)
        );
        let fragment = report.redo().fragments().last().unwrap();
        assert_eq!(fragment.offset(), 100 * 512);
        assert!(fragment.is_write());
        let mut expected = *b"ABCDEFGH";
        if operation == 8 {
            expected = *b"UNDO1234";
        } else {
            for bit in 3usize..13 {
                if operation == 21 {
                    expected[bit / 8] |= 1 << (bit % 8);
                } else {
                    expected[bit / 8] &= !(1 << (bit % 8));
                }
            }
        }
        assert_eq!(&fragment.after()[..8], &expected);
        assert_eq!(fragment.lsn(), lsn(4 * PAGE + 408));
        assert!(!report.recovery_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn native_undo_action_io_error_is_retained_and_overwritten_by_read_next() {
    struct FailUndoRead {
        raw: Image,
        armed: Arc<std::sync::atomic::AtomicBool>,
        reads: Arc<AtomicU64>,
    }
    impl ReadAt for FailUndoRead {
        fn len(&self) -> u64 {
            self.raw.len()
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            if offset == 100 * 512
                && out.len() == 8
                && self.armed.load(Ordering::SeqCst)
                && self.reads.fetch_add(1, Ordering::SeqCst) == 1
            {
                return Err(io::Error::other(
                    "independent one-shot native undo action read failure",
                ));
            }
            self.raw.read_exact_at(offset, out)
        }
    }
    let r = resources();
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reads = Arc::new(AtomicU64::new(0));
    let input = redo_byte_effect_input_source(
        |raw| {
            for slot in [2usize, 4] {
                edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xe402, |page| {
                    w(page, 24, 504);
                    d(page, 408 + 24, 48);
                    q(page, 408 + 16, 0);
                    w(page, 408 + 48 + 2, 8);
                    w(page, 408 + 48 + 8, 40);
                    w(page, 408 + 48 + 10, 8);
                    w(page, 408 + 48 + 12, 24);
                    w(page, 408 + 48 + 14, 1);
                    q(page, 408 + 48 + 24, 0);
                    q(page, 408 + 48 + 32, 100);
                    page[496..504].copy_from_slice(b"UNDO1234");
                });
            }
        },
        |raw| {
            Arc::new(FailUndoRead {
                raw: Image::new(raw),
                armed: armed.clone(),
                reads: reads.clone(),
            })
        },
        &r,
    );
    let redo = inspect_logfile_native_redo(input, redo_limits(), &r).unwrap();
    assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
    armed.store(true, Ordering::SeqCst);
    let report = inspect_logfile_native_undo(redo, undo_limits(), &r).unwrap();
    assert!(
        report.admitted_undo_complete(),
        "{:?}",
        report.stopping_error()
    );
    assert_eq!(
        report.steps()[0].disposition(),
        NtfsLogUndoDisposition::ActionFailed(8)
    );
    assert_eq!(
        report.steps()[0].action_error().unwrap().kind,
        ErrorKind::Io
    );
    assert_eq!(report.redo().fragments().len(), 1);
    assert_eq!(report.redo().fragments()[0].after(), b"ABCDEFGH");
    assert!(
        report
            .transactions()
            .iter()
            .all(|transaction| transaction.released())
    );
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_undo_completed_action_read_survives_post_read_cancellation() {
    struct CancelUndoRead {
        raw: Image,
        armed: Arc<std::sync::atomic::AtomicBool>,
        reads: Arc<AtomicU64>,
        cancellation: Cancellation,
    }
    impl ReadAt for CancelUndoRead {
        fn len(&self) -> u64 {
            self.raw.len()
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            self.raw.read_exact_at(offset, out)?;
            if offset == 100 * 512
                && out.len() == 8
                && self.armed.load(Ordering::SeqCst)
                && self.reads.fetch_add(1, Ordering::SeqCst) == 1
            {
                self.cancellation.cancel();
            }
            Ok(())
        }
    }
    let r = resources();
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reads = Arc::new(AtomicU64::new(0));
    let input = redo_byte_effect_input_source(
        |raw| {
            for slot in [2usize, 4] {
                edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xe402, |page| {
                    w(page, 24, 504);
                    d(page, 408 + 24, 48);
                    q(page, 408 + 16, 0);
                    w(page, 408 + 48 + 2, 8);
                    w(page, 408 + 48 + 8, 40);
                    w(page, 408 + 48 + 10, 8);
                    w(page, 408 + 48 + 12, 24);
                    w(page, 408 + 48 + 14, 1);
                    q(page, 408 + 48 + 24, 0);
                    q(page, 408 + 48 + 32, 100);
                    page[496..504].copy_from_slice(b"UNDO1234");
                });
            }
        },
        |raw| {
            Arc::new(CancelUndoRead {
                raw: Image::new(raw),
                armed: armed.clone(),
                reads: reads.clone(),
                cancellation: r.cancellation.clone(),
            })
        },
        &r,
    );
    let redo = inspect_logfile_native_redo(input, redo_limits(), &r).unwrap();
    assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
    armed.store(true, Ordering::SeqCst);
    let report = inspect_logfile_native_undo(redo, undo_limits(), &r).unwrap();
    assert!(!report.admitted_undo_complete());
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::Cancelled);
    assert_eq!(report.redo().fragments().len(), 2);
    let retained = report.redo().fragments().last().unwrap();
    assert_eq!(retained.offset(), 100 * 512);
    assert!(!retained.is_write());
    assert_eq!(retained.original(), retained.after());
    assert!(
        report
            .transactions()
            .iter()
            .any(|transaction| transaction.active() && !transaction.released())
    );
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

fn mirror_pending_undo(
    r: &Resources,
    source: impl FnOnce(Vec<u8>) -> Arc<dyn ReadAt>,
) -> NtfsLogUndoReport {
    let input = redo_byte_effect_input_source(
        |raw| {
            let current = lsn(4 * PAGE + 504);
            for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
                edit(restart, 0xe201, |page| q(page, 56, current));
            }
            for slot in [2usize, 4] {
                edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xe202, |page| {
                    let noop = page[408..496].to_vec();
                    let action = page[312..400].to_vec();
                    page[504..592].copy_from_slice(&noop);
                    page[408..496].copy_from_slice(&action);
                    page[496..504].copy_from_slice(b"ignored!");
                    w(page, 24, 592);
                    if slot == 4 {
                        q(page, 8, current);
                    }
                    q(page, 32, current);
                    // Keep the source-owned FILE24, but select its genuinely
                    // absent named DATA via the existing UTF16 name payload.
                    w(page, 176 + 48 + 10, 8);
                    q(page, 176 + 48 + 40 + 16, (7u64 << 48) | 2);
                    for start in [312usize, 408] {
                        q(page, start, lsn(4 * PAGE + start));
                        w(page, start + 48, 3);
                        q(page, start + 48 + 24, 4);
                    }
                    q(page, 504, current);
                    q(page, 504 + 16, lsn(4 * PAGE + 408));
                    q(page, 408 + 16, 0);
                    w(page, 408 + 48 + 2, 3);
                });
            }
        },
        |mut volume| {
            use dirty_native_volume_fixture::{name_value, put, resident};
            // Native ni admission requires STANDARD_INFORMATION; the shared
            // audit-only seed intentionally does not provide it for FILE24.
            put(
                &mut volume,
                24,
                &[
                    resident(0x10, &[0; 48], 0),
                    resident(0x30, &name_value("alpha", 5), 1),
                    resident(0x30, &name_value("beta", 5), 2),
                    resident(0x80, b"hello", 3),
                ],
                false,
                2,
            );
            // Native pre-replay mount loads $MFTMirr with sequence1 and SI.
            put(
                &mut volume,
                1,
                &[
                    resident(0x10, &[0; 48], 0),
                    resident(0x30, &name_value("$MFTMirr", 5), 2),
                    dirty_native_volume_fixture::nonresident(
                        &[0x21, 8, 0xf4, 1, 0],
                        8,
                        4096,
                        4096,
                        false,
                    ),
                ],
                false,
                1,
            );
            w(&mut volume, 2048 + 1024 + 16, 1);
            let mirror = volume[2048..6144].to_vec();
            volume[500 * 512..508 * 512].copy_from_slice(&mirror);
            source(volume)
        },
        r,
    );
    assert!(input.dirty_runs_complete(), "{:?}", input.stopping_error());
    let redo = inspect_logfile_native_redo(input, redo_limits(), r).unwrap();
    assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
    let undo = inspect_logfile_native_undo(redo, undo_limits(), r).unwrap();
    assert!(undo.admitted_undo_complete(), "{:?}", undo.stopping_error());
    assert!(undo.redo().runtime_mirror().unwrap().pending());
    undo
}
fn mirror_limits() -> NtfsLogMirrorLimits {
    NtfsLogMirrorLimits {
        blocks: 16,
        bytes: 4 * 4096,
        work: 1024 << 20,
    }
}
#[test]
fn native_post_undo_mirror_copies_contiguous_boot_range_with_latest_file_shadows() {
    let r = resources();
    let undo = mirror_pending_undo(&r, |raw| Arc::new(Image::new(raw)));
    let report = inspect_logfile_native_mirror(undo, mirror_limits(), &r).unwrap();
    assert!(
        report.mirror_copy_complete(),
        "{:?}",
        report.stopping_error()
    );
    assert!(report.native_returned());
    assert_eq!(report.blocks().len(), 8);
    for (ordinal, block) in report.blocks().iter().enumerate() {
        assert_eq!(block.source_offset(), 2048 + ordinal as u64 * 512);
        assert_eq!(block.destination_offset(), 500 * 512 + ordinal as u64 * 512);
        assert!(block.source_original().is_some());
        assert!(block.destination_original().is_some());
        assert_eq!(block.after().unwrap(), block.source_after().unwrap());
    }
    let copied_file = report.blocks()[4].after().unwrap();
    assert_eq!(
        u16::from_le_bytes(copied_file[16..18].try_into().unwrap()),
        10
    );
    assert_eq!(
        u64::from_le_bytes(copied_file[8..16].try_into().unwrap()),
        lsn(4 * PAGE + 408)
    );
    assert!(!report.undo().redo().runtime_mirror().unwrap().pending());
    assert!(!report.active_window_complete());
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn native_post_undo_mirror_provenance_failure_stops_without_inventing_native_read_error() {
    struct FailMirror {
        raw: Image,
        armed: Arc<std::sync::atomic::AtomicBool>,
        fail_offset: u64,
    }
    impl ReadAt for FailMirror {
        fn len(&self) -> u64 {
            self.raw.len()
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            if offset == self.fail_offset
                && out.len() == 512
                && self.armed.swap(false, Ordering::SeqCst)
            {
                return Err(io::Error::other(
                    "independent mirror source provenance acquisition failure",
                ));
            }
            self.raw.read_exact_at(offset, out)
        }
    }
    // Second source case is entirely covered by prior FILE shadow writes.
    // The failed physical read is still an instrumentation refusal, never a
    // fabricated native sb_bread error on an uptodate cached source buffer.
    for (fail_offset, expected_blocks, source_completed) in
        [(2048, 1, false), (4096, 5, false), (500 * 512, 1, true)]
    {
        let r = resources();
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let undo = mirror_pending_undo(&r, |raw| {
            Arc::new(FailMirror {
                raw: Image::new(raw),
                armed: armed.clone(),
                fail_offset,
            })
        });
        armed.store(true, Ordering::SeqCst);
        let report = inspect_logfile_native_mirror(undo, mirror_limits(), &r).unwrap();
        assert!(!report.mirror_copy_complete());
        assert!(!report.native_returned());
        assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::Io);
        assert!(report.undo().redo().runtime_mirror().unwrap().pending());
        assert_eq!(report.blocks().len(), expected_blocks);
        let failed = report.blocks().last().unwrap();
        assert_eq!(failed.source_original().is_some(), source_completed);
        assert_eq!(failed.source_after().is_some(), source_completed);
        assert!(failed.after().is_none());
        for copied in &report.blocks()[..expected_blocks - 1] {
            assert!(copied.after().is_some());
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

fn initialize_pending_undo(
    r: &Resources,
    source: impl FnOnce(Vec<u8>) -> Arc<dyn ReadAt>,
) -> NtfsLogUndoReport {
    let input = redo_byte_effect_input_source(
        |raw| {
            let current = lsn(4 * PAGE + 504);
            for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
                edit(restart, 0xe201, |page| q(page, 56, current));
            }
            for slot in [2usize, 4] {
                edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xe202, |page| {
                    let noop = page[408..496].to_vec();
                    let action = page[312..400].to_vec();
                    page[504..592].copy_from_slice(&noop);
                    page[408..496].copy_from_slice(&action);
                    page[496..504].copy_from_slice(b"ignored!");
                    w(page, 24, 592);
                    if slot == 4 {
                        q(page, 8, current);
                    }
                    q(page, 32, current);
                    // Keep the source-owned FILE24, but select its genuinely
                    // absent named DATA via the existing UTF16 name payload.
                    w(page, 176 + 48 + 10, 8);
                    q(page, 176 + 48 + 40 + 16, (7u64 << 48) | 2);
                    for start in [312usize, 408] {
                        q(page, start, lsn(4 * PAGE + start));
                        w(page, start + 48, 3);
                        q(page, start + 48 + 24, 4);
                    }
                    q(page, 504, current);
                    q(page, 504 + 16, lsn(4 * PAGE + 408));
                    q(page, 408 + 16, 0);
                    w(page, 408 + 48, 2);
                    w(page, 408 + 48 + 2, 2);
                    w(page, 408 + 48 + 4, 40);
                    w(page, 408 + 48 + 6, 8);
                    w(page, 408 + 48 + 8, 40);
                    w(page, 408 + 48 + 10, 8);
                    w(page, 408 + 48 + 16, 100);
                });
            }
        },
        |mut volume| {
            use dirty_native_volume_fixture::{name_value, put, resident};
            // Native ni admission requires STANDARD_INFORMATION; the shared
            // audit-only seed intentionally does not provide it for FILE24.
            put(
                &mut volume,
                24,
                &[
                    resident(0x10, &[0; 48], 0),
                    resident(0x30, &name_value("alpha", 5), 1),
                    resident(0x30, &name_value("beta", 5), 2),
                    resident(0x80, b"hello", 3),
                ],
                false,
                2,
            );
            // Native pre-replay mount loads $MFTMirr with sequence1 and SI.
            put(
                &mut volume,
                1,
                &[
                    resident(0x10, &[0; 48], 0),
                    resident(0x30, &name_value("$MFTMirr", 5), 2),
                    dirty_native_volume_fixture::nonresident(
                        &[0x21, 8, 0xf4, 1, 0],
                        8,
                        4096,
                        4096,
                        false,
                    ),
                ],
                false,
                1,
            );
            w(&mut volume, 2048 + 1024 + 16, 1);
            let mirror = volume[2048..6144].to_vec();
            volume[500 * 512..508 * 512].copy_from_slice(&mirror);
            source(volume)
        },
        r,
    );
    assert!(input.dirty_runs_complete(), "{:?}", input.stopping_error());
    let redo = inspect_logfile_native_redo(input, redo_limits(), r).unwrap();
    assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
    let undo = inspect_logfile_native_undo(redo, undo_limits(), r).unwrap();
    assert!(undo.admitted_undo_complete(), "{:?}", undo.stopping_error());
    assert!(undo.redo().runtime_mirror().unwrap().pending());
    undo
}

#[test]
fn native_initialize_shared_redo_undo_uses_loaded_file_cache_and_mirror_effects() {
    let r = resources();
    let undo = initialize_pending_undo(&r, |raw| Arc::new(Image::new(raw)));
    let file = &undo.redo().runtime_files()[0];
    assert_eq!(&file.bytes()[100..108], b"ignored!");
    assert_eq!(
        u16::from_le_bytes(file.bytes()[16..18].try_into().unwrap()),
        8
    );
    assert_eq!(
        u64::from_le_bytes(file.bytes()[8..16].try_into().unwrap()),
        lsn(4 * PAGE + 408)
    );
    assert_eq!(undo.redo().fragments().len(), 4);
    assert!(!undo.redo().fragments()[0].is_write());
    assert!(
        undo.redo().fragments()[1..]
            .iter()
            .all(|fragment| fragment.is_write())
    );
    assert!(!undo.recovery_complete());
    let report = inspect_logfile_native_mirror(undo, mirror_limits(), &r).unwrap();
    assert!(
        report.mirror_copy_complete(),
        "{:?}",
        report.stopping_error()
    );
    assert!(!report.undo().redo().runtime_mirror().unwrap().pending());
    assert!(!report.recovery_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

// Additional cached Initialize evidence is isolated to preserve the existing
// integration fixtures and assertions byte-for-byte.
mod cached_initialize_evidence {
    use super::*;

    fn initialize_redo_at(
        r: &Resources,
        source: impl FnOnce(Vec<u8>) -> Arc<dyn ReadAt>,
        record_offset: u16,
        first_operation: u16,
        redo_length: u16,
    ) -> NtfsLogRedoReport {
        let input = redo_byte_effect_input_source(
            |raw| {
                let current = lsn(4 * PAGE + 504);
                for restart in raw[..2 * PAGE].chunks_mut(PAGE) {
                    edit(restart, 0xe201, |page| q(page, 56, current));
                }
                for slot in [2usize, 4] {
                    edit(&mut raw[slot * PAGE..(slot + 1) * PAGE], 0xe202, |page| {
                        let noop = page[408..496].to_vec();
                        let action = page[312..400].to_vec();
                        page[504..592].copy_from_slice(&noop);
                        page[408..496].copy_from_slice(&action);
                        page[496..504].copy_from_slice(b"ignored!");
                        w(page, 24, 592);
                        if slot == 4 {
                            q(page, 8, current);
                        }
                        q(page, 32, current);
                        // Keep the source-owned FILE24, but select its genuinely
                        // absent named DATA via the existing UTF16 name payload.
                        w(page, 176 + 48 + 10, 8);
                        q(page, 176 + 48 + 40 + 16, (7u64 << 48) | 2);
                        for start in [312usize, 408] {
                            q(page, start, lsn(4 * PAGE + start));
                            w(page, start + 48, 3);
                            q(page, start + 48 + 24, 4);
                        }
                        q(page, 504, current);
                        q(page, 504 + 16, lsn(4 * PAGE + 408));
                        q(page, 408 + 16, 0);
                        w(page, 408 + 48, 2);
                        w(page, 408 + 48 + 2, 2);
                        w(page, 408 + 48 + 4, 40);
                        w(page, 408 + 48 + 6, redo_length);
                        w(page, 408 + 48 + 8, 40);
                        w(page, 408 + 48 + 10, 8);
                        w(page, 408 + 48 + 16, record_offset);
                        w(page, 312 + 48, first_operation);
                    });
                }
            },
            |mut volume| {
                use dirty_native_volume_fixture::{name_value, put, resident};
                // Native ni admission requires STANDARD_INFORMATION; the shared
                // audit-only seed intentionally does not provide it for FILE24.
                put(
                    &mut volume,
                    24,
                    &[
                        resident(0x10, &[0; 48], 0),
                        resident(0x30, &name_value("alpha", 5), 1),
                        resident(0x30, &name_value("beta", 5), 2),
                        resident(0x80, b"hello", 3),
                    ],
                    false,
                    2,
                );
                // Native pre-replay mount loads $MFTMirr with sequence1 and SI.
                put(
                    &mut volume,
                    1,
                    &[
                        resident(0x10, &[0; 48], 0),
                        resident(0x30, &name_value("$MFTMirr", 5), 2),
                        dirty_native_volume_fixture::nonresident(
                            &[0x21, 8, 0xf4, 1, 0],
                            8,
                            4096,
                            4096,
                            false,
                        ),
                    ],
                    false,
                    1,
                );
                w(&mut volume, 2048 + 1024 + 16, 1);
                let mirror = volume[2048..6144].to_vec();
                volume[500 * 512..508 * 512].copy_from_slice(&mirror);
                source(volume)
            },
            r,
        );
        inspect_logfile_native_redo(input, redo_limits(), r).unwrap()
    }

    #[test]
    fn native_initialize_last_eight_bytes_preserve_usa_and_redo_then_null_undo() {
        let r = resources();
        let redo = initialize_redo_at(&r, |raw| Arc::new(Image::new(raw)), 1016, 3, 8);
        assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
        assert!(!redo.dirty_volume_observed());
        assert_eq!(&redo.runtime_files()[0].bytes()[1016..1024], b"ignored!");
        assert_eq!(
            u64::from_le_bytes(redo.runtime_files()[0].bytes()[8..16].try_into().unwrap()),
            lsn(4 * PAGE + 408)
        );
        assert_eq!(redo.fragments().len(), 3);
        let redo_disk = redo.fragments()[2].after();
        assert!(redo.fragments()[2].is_write());
        assert_eq!(redo.fragments()[2].offset(), 4096);
        assert_eq!(&redo_disk[52..54], b"d!"); // second sector's saved USA tail
        assert_eq!(&redo_disk[1016..1022], b"ignore");
        assert_eq!(&redo_disk[1022..1024], &2u16.to_le_bytes());
        let undo = inspect_logfile_native_undo(redo, undo_limits(), &r).unwrap();
        assert!(undo.admitted_undo_complete(), "{:?}", undo.stopping_error());
        assert_eq!(
            &undo.redo().runtime_files()[0].bytes()[1016..1024],
            b"ignored!"
        );
        assert_eq!(undo.redo().fragments().len(), 4);
        assert!(undo.redo().fragments()[3].is_write());
        let undo_disk = undo.redo().fragments()[3].after().to_vec();
        assert_eq!(&undo_disk[52..54], b"d!");
        assert_eq!(&undo_disk[1016..1022], b"ignore");
        assert_eq!(&undo_disk[1022..1024], &3u16.to_le_bytes());
        let mirror = inspect_logfile_native_mirror(undo, mirror_limits(), &r).unwrap();
        assert!(
            mirror.mirror_copy_complete(),
            "{:?}",
            mirror.stopping_error()
        );
        assert!(mirror.native_returned());
        assert_eq!(mirror.blocks().len(), 8);
        let first = &mirror.blocks()[4];
        let second = &mirror.blocks()[5];
        assert_eq!(first.source_offset(), 4096);
        assert_eq!(second.source_offset(), 4608);
        assert_eq!(first.destination_offset(), 500 * 512 + 4 * 512);
        assert_eq!(second.destination_offset(), 500 * 512 + 5 * 512);
        assert_eq!(first.after().unwrap(), &undo_disk[..512]);
        assert_eq!(second.after().unwrap(), &undo_disk[512..]);
        assert_eq!(&first.after().unwrap()[52..54], b"d!");
        assert_eq!(&second.after().unwrap()[504..510], b"ignore");
        assert_eq!(&second.after().unwrap()[510..512], &3u16.to_le_bytes());
        assert!(!mirror.undo().redo().runtime_mirror().unwrap().pending());
        assert!(!mirror.recovery_complete());
        drop(mirror);
        assert_eq!(r.memory.used(), 0);
    }

    #[test]
    fn native_initialize_payload_lsn_is_overridden_only_by_redo() {
        let r = resources();
        let redo = initialize_redo_at(&r, |raw| Arc::new(Image::new(raw)), 8, 3, 8);
        assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
        assert_eq!(
            u64::from_le_bytes(redo.runtime_files()[0].bytes()[8..16].try_into().unwrap()),
            lsn(4 * PAGE + 408)
        );
        let undo = inspect_logfile_native_undo(redo, undo_limits(), &r).unwrap();
        assert!(undo.admitted_undo_complete(), "{:?}", undo.stopping_error());
        // NULL undo LSN suppresses only the automatic store. The undo payload
        // itself is still allowed to overwrite the record's eight LSN bytes.
        assert_eq!(&undo.redo().runtime_files()[0].bytes()[8..16], b"ignored!");
        drop(undo);
        assert_eq!(r.memory.used(), 0);
    }

    #[test]
    fn native_initialize_outside_record_marks_dirty_without_extra_file_effects() {
        for offset in [1020, u16::MAX] {
            let r = resources();
            let redo = initialize_redo_at(&r, |raw| Arc::new(Image::new(raw)), offset, 3, 8);
            assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
            assert!(redo.dirty_volume_observed());
            assert_eq!(redo.fragments().len(), 2); // original acquisition + preceding deallocation only
            let cached = redo.runtime_files()[0].bytes().to_vec();
            assert_eq!(
                u64::from_le_bytes(cached[8..16].try_into().unwrap()),
                lsn(4 * PAGE + 312)
            );
            let undo = inspect_logfile_native_undo(redo, undo_limits(), &r).unwrap();
            assert!(undo.admitted_undo_complete(), "{:?}", undo.stopping_error());
            assert!(undo.redo().dirty_volume_observed());
            assert_eq!(undo.redo().runtime_files()[0].bytes(), cached);
            assert_eq!(undo.redo().fragments().len(), 2);
            assert!(undo.redo().runtime_mirror().unwrap().pending()); // prior deallocation effect retained
            drop(undo);
            assert_eq!(r.memory.used(), 0);
        }
    }

    #[test]
    fn native_initialize_reference_only_target_refuses_uncached_format_without_file_effects() {
        let r = resources();
        let redo = initialize_redo_at(&r, |raw| Arc::new(Image::new(raw)), 100, 0, 8);
        assert!(!redo.admitted_redo_complete());
        let error = redo.stopping_error().unwrap();
        assert_eq!(error.kind, ErrorKind::Unsupported);
        assert!(redo.runtime_files().is_empty());
        assert!(redo.fragments().is_empty());
        assert!(!redo.runtime_mirror().unwrap().pending());
        drop(redo);
        assert_eq!(r.memory.used(), 0);
    }

    #[test]
    fn native_initialize_declared_payload_exceeding_frame_refuses_before_file_effects() {
        let r = resources();
        let redo = initialize_redo_at(&r, |raw| Arc::new(Image::new(raw)), 100, 0, u16::MAX);
        assert!(!redo.admitted_redo_complete());
        assert!(redo.stopping_error().is_some());
        assert!(redo.runtime_files().is_empty());
        assert!(redo.fragments().is_empty());
        drop(redo);
        assert_eq!(r.memory.used(), 0);
    }

    #[test]
    fn native_initialize_undo_rechecks_original_physical_provenance_after_redo() {
        struct Drift {
            raw: Image,
            armed: Arc<std::sync::atomic::AtomicBool>,
        }
        impl ReadAt for Drift {
            fn len(&self) -> u64 {
                self.raw.len()
            }
            fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
                self.raw.read_exact_at(offset, out)?;
                if self.armed.load(Ordering::SeqCst)
                    && offset <= 4096
                    && 4096 - offset < out.len() as u64
                {
                    out[(4096 - offset) as usize] ^= 1;
                }
                Ok(())
            }
        }
        let r = resources();
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let redo = initialize_redo_at(
            &r,
            |raw| {
                Arc::new(Drift {
                    raw: Image::new(raw),
                    armed: armed.clone(),
                })
            },
            100,
            3,
            8,
        );
        assert!(redo.admitted_redo_complete(), "{:?}", redo.stopping_error());
        let count = redo.fragments().len();
        armed.store(true, Ordering::SeqCst);
        let undo = inspect_logfile_native_undo(redo, undo_limits(), &r).unwrap();
        assert!(!undo.admitted_undo_complete());
        assert_eq!(undo.stopping_error().unwrap().kind, ErrorKind::StalePlan);
        assert_eq!(undo.redo().fragments().len(), count);
        assert!(undo.redo().runtime_mirror().unwrap().pending());
        drop(undo);
        assert_eq!(r.memory.used(), 0);
    }
}
