#![cfg(feature = "std")]

// Hand-authored restart structures from the published NTFS LFS layouts. No
// production encoder or checksum/fixup helper constructs the expected bytes.
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    io,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use virtdisk::ReadAt;

const PAGE: usize = 4096;
const AREA: usize = 56;
const CLIENT: usize = AREA + 64;
const LENGTH: usize = 64 * PAGE;
fn w(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn d(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn q(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn restart_page(clean: bool, usn: u16) -> Vec<u8> {
    let mut bytes = vec![0; PAGE];
    bytes[..4].copy_from_slice(b"RSTR");
    w(&mut bytes, 4, 32);
    w(&mut bytes, 6, 9);
    d(&mut bytes, 16, PAGE as u32);
    d(&mut bytes, 20, PAGE as u32);
    w(&mut bytes, 24, AREA as u16);
    w(&mut bytes, 26, 1);
    w(&mut bytes, 28, 1);
    w(&mut bytes, AREA + 8, 1);
    w(&mut bytes, AREA + 10, u16::MAX);
    w(&mut bytes, AREA + 12, 0);
    w(&mut bytes, AREA + 14, if clean { 2 } else { 0 });
    d(&mut bytes, AREA + 16, 48);
    w(&mut bytes, AREA + 20, 224);
    w(&mut bytes, AREA + 22, 64);
    q(&mut bytes, AREA + 24, LENGTH as u64);
    w(&mut bytes, AREA + 36, 48);
    w(&mut bytes, AREA + 38, 64);
    d(&mut bytes, AREA + 40, 17);
    w(&mut bytes, CLIENT + 16, u16::MAX);
    w(&mut bytes, CLIENT + 18, u16::MAX);
    d(&mut bytes, CLIENT + 28, 8);
    for (i, unit) in "NTFS".encode_utf16().enumerate() {
        w(&mut bytes, CLIENT + 32 + i * 2, unit);
    }
    w(&mut bytes, 32, usn);
    for sector in 1..=8 {
        let offset = sector * 512 - 2;
        let old = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        w(&mut bytes, 32 + sector * 2, old);
        w(&mut bytes, offset, usn);
    }
    bytes
}
fn restart_fixture(clean: bool) -> Vec<u8> {
    let mut bytes = vec![0xff; LENGTH];
    bytes[..PAGE].copy_from_slice(&restart_page(clean, 0xa55a));
    bytes[PAGE..2 * PAGE].copy_from_slice(&restart_page(clean, 0x7e21));
    bytes
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    }
}
struct Image {
    bytes: Vec<u8>,
    reads: AtomicU64,
    fail: AtomicU64,
    length: AtomicU64,
}
impl Image {
    fn new(bytes: Vec<u8>) -> Self {
        let length = bytes.len() as u64;
        Self {
            bytes,
            reads: AtomicU64::new(0),
            fail: AtomicU64::new(u64::MAX),
            length: AtomicU64::new(length),
        }
    }
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.length.load(Ordering::Relaxed)
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if offset >= self.fail.load(Ordering::Relaxed) {
            return Err(io::Error::other("injected logfile I/O failure"));
        }
        let offset = usize::try_from(offset).map_err(io::Error::other)?;
        bytes.copy_from_slice(
            self.bytes
                .get(offset..offset + bytes.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
}

use partmgr::fs_ntfs_logfile::{
    NtfsLogFileLimits, NtfsLogPageKind, NtfsLogPageLimits, NtfsLogPageRole, inspect_logfile_pages,
};
fn log_limits() -> NtfsLogFileLimits {
    NtfsLogFileLimits {
        restart_page_bytes: PAGE,
        clients: 16,
        work: 10000,
    }
}
fn page_limits() -> NtfsLogPageLimits {
    NtfsLogPageLimits {
        pages: 64,
        retained_bytes: 64 * PAGE,
        work: 10000,
    }
}
fn record_page(value: u64, flags: u32, usn: u16) -> Vec<u8> {
    let mut bytes = vec![0; PAGE];
    bytes[..4].copy_from_slice(b"RCRD");
    w(&mut bytes, 4, 40);
    w(&mut bytes, 6, 9);
    q(&mut bytes, 8, value);
    d(&mut bytes, 16, flags);
    w(&mut bytes, 20, 1);
    w(&mut bytes, 22, 1);
    w(&mut bytes, 24, 64);
    q(&mut bytes, 32, 0x5678);
    // Nonzero final words ensure USA restoration is checked instead of merely
    // comparing trailer markers over an all-zero record.
    for sector in 1..=8 {
        w(&mut bytes, sector * 512 - 2, 0x1000 + sector as u16);
    }
    w(&mut bytes, 40, usn);
    for sector in 1..=8 {
        let at = sector * 512 - 2;
        let old = u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        w(&mut bytes, 40 + sector * 2, old);
        w(&mut bytes, at, usn);
    }
    bytes
}
fn fixture() -> Vec<u8> {
    let mut bytes = restart_fixture(true);
    for index in 2..64 {
        let page = record_page(
            if index < 4 {
                (index as u64 + 2) * PAGE as u64
            } else {
                0x1234 + index as u64
            },
            1,
            0x7d00 + index as u16,
        );
        bytes[index * PAGE..(index + 1) * PAGE].copy_from_slice(&page);
    }
    bytes
}
#[test]
fn physical_inventory_distinguishes_tail_copies_and_ordinary_pages_without_lsn_selection() {
    let bytes = fixture();
    let expected = bytes.clone();
    let r = resources();
    let report =
        inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
            .unwrap();
    assert!(report.scan_complete());
    assert!(report.stopping_error().is_none());
    assert!(!report.transaction_analysis_complete());
    assert_eq!(report.pages().len(), 62);
    for (i, page) in report.pages().iter().enumerate() {
        assert_eq!(page.offset(), ((i + 2) * PAGE) as u64);
        assert_eq!(
            page.role(),
            if i < 2 {
                NtfsLogPageRole::TailCopy { index: i as u8 }
            } else {
                NtfsLogPageRole::Ordinary
            }
        );
        assert_eq!(page.kind(), NtfsLogPageKind::Record);
        assert!(page.read_complete());
        assert_eq!(page.raw(), &expected[(i + 2) * PAGE..(i + 3) * PAGE]);
        let header = page.header().unwrap();
        assert_eq!(header.flags, 1);
        assert_eq!(header.page_count, 1);
        assert_eq!(header.page_position, 1);
        assert_eq!(header.next_record_offset, 64);
        assert_eq!(header.last_end_lsn, 0x5678);
        assert_eq!(
            header.raw_lsn_or_file_offset,
            if i < 2 {
                (i as u64 + 4) * PAGE as u64
            } else {
                0x1234 + i as u64 + 2
            }
        );
    }
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn independent_transfer_trailer_corruptions_are_per_page_findings() {
    for sector in [1, 8] {
        let mut bytes = fixture();
        bytes[4 * PAGE + sector * 512 - 2] ^= 1;
        let r = resources();
        let report =
            inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
                .unwrap();
        assert!(report.scan_complete());
        assert_eq!(
            report.pages()[2].error().unwrap().kind,
            ErrorKind::InvalidData
        );
        assert!(report.pages()[1].header().is_some());
        assert!(report.pages()[3].header().is_some());
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn page_header_usa_and_record_offsets_are_bounded() {
    for mutation in 0..9 {
        let mut bytes = fixture();
        let start = 4 * PAGE;
        match mutation {
            0 => w(&mut bytes, start + 4, 38),
            1 => w(&mut bytes, start + 4, 41),
            2 => w(&mut bytes, start + 6, 8),
            3 => w(&mut bytes, start + 4, 4094),
            4 => w(&mut bytes, start + 24, 56),
            5 => w(&mut bytes, start + 24, 65),
            6 => w(&mut bytes, start + 24, 4097),
            7 => w(&mut bytes, start + 20, 0),
            _ => w(&mut bytes, start + 22, 0),
        }
        let r = resources();
        let report =
            inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
                .unwrap();
        assert!(report.pages()[2].error().is_some(), "mutation {mutation}");
        assert!(report.scan_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn page_position_must_fit_page_count_but_multpage_assembly_is_not_claimed() {
    for position in [1, 2, 3] {
        let mut bytes = fixture();
        w(&mut bytes, 4 * PAGE + 20, 2);
        w(&mut bytes, 4 * PAGE + 22, position);
        let r = resources();
        let report =
            inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
                .unwrap();
        assert_eq!(report.pages()[2].error().is_none(), position <= 2);
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn erased_and_unknown_pages_remain_visible_and_never_become_record_headers() {
    let mut bytes = fixture();
    bytes[4 * PAGE..5 * PAGE].fill(0);
    bytes[5 * PAGE..6 * PAGE].fill(0xff);
    bytes[6 * PAGE..6 * PAGE + 4].copy_from_slice(b"XXXX");
    let r = resources();
    let report =
        inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
            .unwrap();
    assert!(report.scan_complete());
    assert_eq!(report.pages()[2].kind(), NtfsLogPageKind::UninitializedZero);
    assert_eq!(report.pages()[3].kind(), NtfsLogPageKind::UninitializedOnes);
    assert_eq!(report.pages()[4].kind(), NtfsLogPageKind::Unknown);
    assert!(
        report.pages()[2..5]
            .iter()
            .all(|page| page.header().is_none() && page.read_complete())
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn page_and_retention_caps_stop_after_retained_evidence_and_refund() {
    for mutation in 0..2 {
        let r = resources();
        let mut cap = page_limits();
        if mutation == 0 {
            cap.pages = 3;
        } else {
            cap.retained_bytes = 3 * PAGE;
        }
        let report =
            inspect_logfile_pages(Arc::new(Image::new(fixture())), log_limits(), cap, &r).unwrap();
        assert!(!report.scan_complete());
        assert_eq!(
            report.stopping_error().unwrap().kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(report.pages().len(), 3);
        assert!(report.pages().iter().all(|page| page.header().is_some()));
        assert!(r.memory.used() > 0);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn late_io_preserves_earlier_pages_and_the_original_cause() {
    let image = Arc::new(Image::new(fixture()));
    image.fail.store((6 * PAGE) as u64, Ordering::Relaxed);
    let r = resources();
    let report = inspect_logfile_pages(image, log_limits(), page_limits(), &r).unwrap();
    assert!(!report.scan_complete());
    assert!(
        report
            .pages()
            .iter()
            .take(4)
            .all(|page| page.header().is_some())
    );
    let error = report.stopping_error().unwrap();
    assert_eq!(error.kind, ErrorKind::Io);
    assert!(error.source.is_some());
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
struct CancelDuringPages {
    image: Image,
    cancellation: Cancellation,
}
impl ReadAt for CancelDuringPages {
    fn len(&self) -> u64 {
        self.image.len()
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.image.read_exact_at(offset, bytes)?;
        if offset == 6 * PAGE as u64 {
            self.cancellation.cancel();
        }
        Ok(())
    }
}
#[test]
fn cancellation_during_later_page_read_keeps_partial_inventory() {
    let r = resources();
    let source = Arc::new(CancelDuringPages {
        image: Image::new(fixture()),
        cancellation: r.cancellation.clone(),
    });
    let report = inspect_logfile_pages(source, log_limits(), page_limits(), &r).unwrap();
    assert!(!report.scan_complete());
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::Cancelled);
    assert!(
        report
            .pages()
            .iter()
            .take(4)
            .all(|page| page.header().is_some())
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
struct ChangeDuringPages(Image);
impl ReadAt for ChangeDuringPages {
    fn len(&self) -> u64 {
        self.0.len()
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(offset, bytes)?;
        if offset == 6 * PAGE as u64 {
            self.0.length.fetch_sub(PAGE as u64, Ordering::Relaxed);
        }
        Ok(())
    }
}
#[test]
fn source_length_change_during_page_scan_invalidates_completion() {
    let r = resources();
    let report = inspect_logfile_pages(
        Arc::new(ChangeDuringPages(Image::new(fixture()))),
        log_limits(),
        page_limits(),
        &r,
    )
    .unwrap();
    assert!(!report.scan_complete());
    assert_eq!(report.stopping_error().unwrap().kind, ErrorKind::StalePlan);
    assert!(
        report
            .pages()
            .iter()
            .take(4)
            .all(|page| page.header().is_some())
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn pre_cancel_and_tiny_memory_fail_without_leaked_reservations() {
    let source = Arc::new(Image::new(fixture()));
    let r = resources();
    r.cancellation.cancel();
    assert_eq!(
        inspect_logfile_pages(source.clone(), log_limits(), page_limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);
    assert_eq!(r.memory.used(), 0);
    let r = Resources {
        memory: Budget::new(1),
        cancellation: Cancellation::default(),
    };
    assert_eq!(
        inspect_logfile_pages(source, log_limits(), page_limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn unknown_flags_keep_validated_raw_fields_without_semantic_support() {
    let mut bytes = fixture();
    d(&mut bytes, 4 * PAGE + 16, 0x80000001);
    let r = resources();
    let report =
        inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
            .unwrap();
    let page = &report.pages()[2];
    assert!(report.scan_complete());
    assert!(page.framing_valid());
    assert!(!page.semantics_supported());
    assert_eq!(page.header().unwrap().flags, 0x80000001);
    assert_eq!(page.error().unwrap().kind, ErrorKind::Unsupported);
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn tail_union_does_not_trigger_ordinary_lsn_based_offset_validation() {
    let mut bytes = fixture();
    w(&mut bytes, 2 * PAGE + 24, 0);
    w(&mut bytes, 4 * PAGE + 24, 0);
    let r = resources();
    let report =
        inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
            .unwrap();
    assert!(report.pages()[0].framing_valid());
    assert!(
        !report.pages()[0]
            .header()
            .unwrap()
            .next_record_offset_checked
    );
    assert_eq!(
        report.pages()[2].error().unwrap().kind,
        ErrorKind::InvalidData
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn exhausted_work_preserves_report_without_claiming_complete_scan() {
    for work in [0, 12] {
        let r = resources();
        let mut cap = page_limits();
        cap.work = work;
        let report =
            inspect_logfile_pages(Arc::new(Image::new(fixture())), log_limits(), cap, &r).unwrap();
        assert!(!report.scan_complete());
        assert_eq!(
            report.stopping_error().unwrap().kind,
            ErrorKind::BudgetExhausted
        );
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn truncated_supplied_stream_keeps_restart_and_explicit_scan_failure() {
    let mut bytes = fixture();
    bytes.truncate(LENGTH - 1);
    let r = resources();
    let report =
        inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
            .unwrap();
    assert!(!report.scan_complete());
    assert!(report.stopping_error().is_some());
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn ordinary_next_record_offset_is_checked_only_under_native_local_end_condition() {
    for (flags, lsn) in [(0, 0x1234), (1, 0x9999)] {
        let mut bytes = fixture();
        d(&mut bytes, 4 * PAGE + 16, flags);
        q(&mut bytes, 4 * PAGE + 8, lsn);
        w(&mut bytes, 4 * PAGE + 24, 0);
        let r = resources();
        let report =
            inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
                .unwrap();
        let page = &report.pages()[2];
        assert!(page.error().is_none());
        assert!(page.framing_valid());
        assert!(!page.header().unwrap().next_record_offset_checked);
        assert_eq!(page.header().unwrap().next_record_offset, 0);
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

struct EmbeddedFailure {
    image: Image,
    kind: ErrorKind,
}
impl ReadAt for EmbeddedFailure {
    fn len(&self) -> u64 {
        self.image.len()
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        if offset == 6 * PAGE as u64 {
            return Err(io::Error::other(partmgr::fs_core::Error::new(
                self.kind,
                "injected structured backend failure",
            )));
        }
        self.image.read_exact_at(offset, bytes)
    }
}
#[test]
fn structured_backend_errors_stop_scan_even_when_kind_matches_local_format_failure() {
    for kind in [ErrorKind::InvalidData, ErrorKind::Unsupported] {
        let r = resources();
        let report = inspect_logfile_pages(
            Arc::new(EmbeddedFailure {
                image: Image::new(fixture()),
                kind,
            }),
            log_limits(),
            page_limits(),
            &r,
        )
        .unwrap();
        assert!(!report.scan_complete());
        assert_eq!(report.pages().len(), 5);
        assert!(report.pages()[..4].iter().all(|page| page.framing_valid()));
        let failed = &report.pages()[4];
        assert_eq!(failed.offset(), 6 * PAGE as u64);
        assert!(!failed.read_complete());
        assert!(!failed.framing_valid());
        let error = report.stopping_error().unwrap();
        assert_eq!(error.kind, kind);
        let cause = error
            .source
            .as_ref()
            .unwrap()
            .get_ref()
            .unwrap()
            .downcast_ref::<partmgr::fs_core::Error>()
            .unwrap();
        assert_eq!(cause.kind, kind);
        assert_eq!(cause.context, "injected structured backend failure");
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

fn version_two_fixture() -> Vec<u8> {
    let mut bytes = restart_fixture(false);
    for offset in [0, PAGE] {
        w(&mut bytes, offset + 26, 0);
        w(&mut bytes, offset + 28, 2);
    }
    for index in 2..64 {
        let mut page = record_page(0x1234, 1, 0xb000 + index as u16);
        if index < 34 {
            d(&mut page, 60, ((34 + (index - 2) % 30) * PAGE) as u32);
        }
        bytes[index * PAGE..(index + 1) * PAGE].copy_from_slice(&page);
    }
    bytes
}
#[test]
fn version_two_inventory_separates_32_fast_copy_targets_from_the_lsn_at_offset_eight() {
    let bytes = version_two_fixture();
    let expected = bytes.clone();
    let r = resources();
    let report =
        inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
            .unwrap();
    assert!(report.scan_complete());
    assert!(report.stopping_error().is_none());
    assert_eq!(report.pages().len(), 62);
    for (index, page) in report.pages().iter().enumerate() {
        assert_eq!(page.offset(), ((index + 2) * PAGE) as u64);
        assert!(page.framing_valid());
        assert!(page.semantics_supported());
        assert_eq!(
            page.raw(),
            &expected[(index + 2) * PAGE..(index + 3) * PAGE]
        );
        let header = page.header().unwrap();
        assert_eq!(header.raw_lsn_or_file_offset, 0x1234);
        if index < 32 {
            assert_eq!(
                page.role(),
                NtfsLogPageRole::FastCopy { index: index as u8 }
            );
            assert_eq!(
                header.fast_copy_target,
                Some(((34 + index % 30) * PAGE) as u32)
            );
            assert!(header.fast_copy_target_checked);
            assert_ne!(
                header.raw_lsn_or_file_offset,
                u64::from(header.fast_copy_target.unwrap())
            );
        } else {
            assert_eq!(page.role(), NtfsLogPageRole::Ordinary);
            assert_eq!(header.fast_copy_target, None);
            assert!(!header.fast_copy_target_checked);
        }
        assert!(header.next_record_offset_checked);
    }
    assert!(!report.active_window_complete());
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn malformed_fast_copy_destinations_remain_local_findings_with_raw_target_preserved() {
    for target in [
        0,
        33 * PAGE as u32,
        34 * PAGE as u32 + 1,
        LENGTH as u32,
        u32::MAX,
    ] {
        let mut bytes = version_two_fixture();
        d(&mut bytes, 2 * PAGE + 60, target);
        let r = resources();
        let report =
            inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
                .unwrap();
        assert!(report.scan_complete());
        assert!(report.stopping_error().is_none());
        let page = &report.pages()[0];
        assert!(page.framing_valid());
        assert!(!page.semantics_supported());
        assert_eq!(page.header().unwrap().fast_copy_target, Some(target));
        assert!(!page.header().unwrap().fast_copy_target_checked);
        assert_eq!(page.error().unwrap().kind, ErrorKind::InvalidData);
        assert!(
            report.pages()[1..]
                .iter()
                .all(|page| page.error().is_none())
        );
        assert!(!report.active_window_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn fast_copy_usa_array_cannot_overlap_the_target_field() {
    let mut bytes = version_two_fixture();
    w(&mut bytes, 2 * PAGE + 4, 44);
    let r = resources();
    let report =
        inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
            .unwrap();
    assert!(report.scan_complete());
    let page = &report.pages()[0];
    assert!(!page.framing_valid());
    assert!(page.header().is_none());
    assert_eq!(page.error().unwrap().kind, ErrorKind::InvalidData);
    assert_eq!(&page.raw()[60..64], &(34 * PAGE as u32).to_le_bytes());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn mixed_restart_versions_never_select_a_physical_topology() {
    let mut bytes = version_two_fixture();
    w(&mut bytes, PAGE + 26, 1);
    w(&mut bytes, PAGE + 28, 1);
    let r = resources();
    let report =
        inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
            .unwrap();
    assert!(!report.scan_complete());
    assert!(report.pages().is_empty());
    assert!(report.restart().copies_disagree());
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::Unsupported
    );
    assert!(!report.active_window_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn divergent_two_zero_restart_lsns_allow_inventory_without_copy_selection() {
    let mut bytes = version_two_fixture();
    q(&mut bytes, PAGE + AREA, 0x12345678);
    let r = resources();
    let report =
        inspect_logfile_pages(Arc::new(Image::new(bytes)), log_limits(), page_limits(), &r)
            .unwrap();
    assert!(report.scan_complete());
    assert!(report.restart().copies_disagree());
    assert_eq!(report.pages().len(), 62);
    assert_eq!(
        report.restart().state(),
        partmgr::fs_ntfs_logfile::NtfsLogFileState::Incomplete
    );
    assert!(!report.active_window_complete());
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn fast_copy_slot_budget_stops_before_ordinary_pages_without_claiming_completion() {
    let r = resources();
    let report = inspect_logfile_pages(
        Arc::new(Image::new(version_two_fixture())),
        log_limits(),
        NtfsLogPageLimits {
            pages: 32,
            ..page_limits()
        },
        &r,
    )
    .unwrap();
    assert!(!report.scan_complete());
    assert_eq!(report.pages().len(), 32);
    assert_eq!(
        report.pages().last().unwrap().role(),
        NtfsLogPageRole::FastCopy { index: 31 }
    );
    assert_eq!(
        report.stopping_error().unwrap().kind,
        ErrorKind::BudgetExhausted
    );
    assert!(!report.active_window_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
