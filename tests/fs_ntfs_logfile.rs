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
fn fixture(clean: bool) -> Vec<u8> {
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
    NtfsLogFileLimits, NtfsLogFileState, NtfsRestartPageKind, inspect_logfile,
};
fn limits() -> NtfsLogFileLimits {
    NtfsLogFileLimits {
        restart_page_bytes: PAGE,
        clients: 16,
        work: 10000,
    }
}
#[test]
fn matching_clean_restart_markers_preserve_bytes_and_do_not_claim_transaction_analysis() {
    let bytes = fixture(true);
    let expected = bytes.clone();
    let r = resources();
    let report = inspect_logfile(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
    assert_eq!(report.state(), NtfsLogFileState::CleanFlagObserved);
    assert!(!report.transaction_analysis_complete());
    assert!(!report.copies_disagree());
    assert!(report.source_error().is_none());
    for (i, copy) in report.copies().iter().enumerate() {
        assert_eq!(copy.offset(), (i * PAGE) as u64);
        assert!(copy.read_complete());
        assert_eq!(copy.kind(), NtfsRestartPageKind::Restart);
        assert_eq!(copy.raw(), &expected[i * PAGE..(i + 1) * PAGE]);
        let area = copy.area().unwrap();
        assert_eq!(area.version, (1, 1));
        assert_eq!(area.flags, 2);
        assert_eq!(area.current_lsn, 0);
        assert_eq!(area.file_bytes, LENGTH as u64);
        assert_eq!(area.sequence_bits, 48);
        assert_eq!(area.client_count, 1);
        assert_eq!(area.free_head, u16::MAX);
        assert_eq!(area.in_use_head, 0);
        assert_eq!(area.record_header_bytes, 48);
        assert_eq!(area.page_data_offset, 64);
        assert_eq!(area.open_count, 17);
    }
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn matching_open_dirty_restart_markers_require_recovery() {
    let r = resources();
    let report = inspect_logfile(Arc::new(Image::new(fixture(false))), limits(), &r).unwrap();
    assert_eq!(report.state(), NtfsLogFileState::RecoveryRequired);
    assert!(!report.transaction_analysis_complete());
    assert!(!report.copies_disagree());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn each_torn_restart_copy_is_diagnostic_and_suppresses_clean_claim() {
    for copy in 0..2 {
        for sector in [1, 8] {
            let mut bytes = fixture(true);
            bytes[copy * PAGE + sector * 512 - 2] ^= 1;
            let r = resources();
            let report = inspect_logfile(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
            assert_ne!(report.state(), NtfsLogFileState::CleanFlagObserved);
            assert_eq!(
                report.copies()[copy].area().unwrap_err().kind,
                ErrorKind::InvalidData
            );
            assert!(report.copies()[1 - copy].area().is_ok());
            drop(report);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
#[test]
fn restart_header_and_area_bounds_are_checked_independently() {
    for mutation in 0..12 {
        let mut bytes = fixture(true);
        match mutation {
            0 => w(&mut bytes, 4, 4094),
            1 => w(&mut bytes, 6, 8),
            2 => d(&mut bytes, 16, 2048),
            3 => d(&mut bytes, 20, 513),
            4 => w(&mut bytes, 24, 57),
            5 => w(&mut bytes, 24, 4088),
            6 => w(&mut bytes, AREA + 20, 32),
            7 => w(&mut bytes, AREA + 22, 65),
            8 => q(&mut bytes, AREA + 24, (LENGTH + PAGE) as u64),
            9 => d(&mut bytes, AREA + 16, 47),
            10 => w(&mut bytes, AREA + 36, 49),
            _ => w(&mut bytes, AREA + 38, 65),
        }
        let r = resources();
        let report = inspect_logfile(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
        assert!(report.copies()[0].area().is_err(), "mutation {mutation}");
        assert_ne!(report.state(), NtfsLogFileState::CleanFlagObserved);
        assert!(report.copies()[1].area().is_ok());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn unsupported_version_geometry_and_flags_are_not_recovery_or_clean() {
    for mutation in 0..4 {
        let mut bytes = fixture(true);
        for copy in 0..2 {
            let base = copy * PAGE;
            match mutation {
                0 => w(&mut bytes, base + 28, 2),
                1 => w(&mut bytes, base + 26, 2),
                2 => d(&mut bytes, base + 20, 8192),
                _ => w(&mut bytes, base + AREA + 14, 4),
            }
        }
        let r = resources();
        let report = inspect_logfile(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
        assert_eq!(
            report.state(),
            NtfsLogFileState::Unsupported,
            "mutation {mutation}"
        );
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn malformed_client_names_and_link_lists_never_supply_clean_evidence() {
    for mutation in 0..8 {
        let mut bytes = fixture(true);
        match mutation {
            0 => w(&mut bytes, AREA + 12, 1),
            1 => w(&mut bytes, AREA + 10, 0),
            2 => w(&mut bytes, CLIENT + 16, 0),
            3 => w(&mut bytes, CLIENT + 18, 0),
            4 => d(&mut bytes, CLIENT + 28, 7),
            5 => d(&mut bytes, CLIENT + 28, 66),
            6 => w(&mut bytes, CLIENT + 32, b'X' as u16),
            _ => {
                w(&mut bytes, AREA + 10, u16::MAX);
                w(&mut bytes, AREA + 12, u16::MAX);
            }
        }
        let r = resources();
        let report = inspect_logfile(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
        assert!(report.copies()[0].area().is_err(), "mutation {mutation}");
        assert_ne!(report.state(), NtfsLogFileState::CleanFlagObserved);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn mismatched_valid_copies_do_not_select_a_newer_restart_by_guessing() {
    for mutation in 0..4 {
        let mut bytes = fixture(true);
        match mutation {
            0 => q(&mut bytes, PAGE + AREA, 0x1234),
            1 => w(&mut bytes, PAGE + AREA + 14, 0),
            2 => d(&mut bytes, PAGE + AREA + 40, 18),
            _ => w(&mut bytes, PAGE + CLIENT + 20, 1),
        }
        let r = resources();
        let report = inspect_logfile(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
        assert!(report.copies().iter().all(|copy| copy.area().is_ok()));
        assert!(report.copies_disagree(), "mutation {mutation}");
        assert_ne!(report.state(), NtfsLogFileState::CleanFlagObserved);
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn erased_and_zero_restart_storage_are_not_clean_restart_records() {
    for byte in [0, 0xff] {
        let r = resources();
        let report =
            inspect_logfile(Arc::new(Image::new(vec![byte; LENGTH])), limits(), &r).unwrap();
        assert_ne!(report.state(), NtfsLogFileState::CleanFlagObserved);
        assert!(!report.transaction_analysis_complete());
        assert!(report.copies().iter().all(|copy| copy.area().is_err()));
        assert!(report.copies().iter().all(|copy| copy.read_complete()
            && copy.kind()
                == if byte == 0 {
                    NtfsRestartPageKind::UninitializedZero
                } else {
                    NtfsRestartPageKind::UninitializedOnes
                }));
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn budgets_and_precancel_fail_without_leaking_memory() {
    let source = Arc::new(Image::new(fixture(true)));
    let r = resources();
    r.cancellation.cancel();
    assert_eq!(
        inspect_logfile(source.clone(), limits(), &r)
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
        inspect_logfile(source.clone(), limits(), &r)
            .err()
            .unwrap()
            .kind,
        ErrorKind::BudgetExhausted
    );
    assert_eq!(r.memory.used(), 0);
    for mutation in 0..3 {
        let r = resources();
        let mut cap = limits();
        match mutation {
            0 => cap.restart_page_bytes = 512,
            1 => cap.clients = 0,
            _ => cap.work = 0,
        };
        match inspect_logfile(source.clone(), cap, &r) {
            Err(error) => assert!(matches!(
                error.kind,
                ErrorKind::BudgetExhausted | ErrorKind::InvalidOperation | ErrorKind::InvalidData
            )),
            Ok(report) => {
                assert_ne!(report.state(), NtfsLogFileState::CleanFlagObserved);
                assert!(report.copies().iter().any(|copy| copy.area().is_err()));
            }
        }
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn io_failure_preserves_independent_other_copy_and_original_error() {
    let source = Arc::new(Image::new(fixture(true)));
    source.fail.store(PAGE as u64, Ordering::Relaxed);
    let r = resources();
    let report = inspect_logfile(source, limits(), &r).unwrap();
    assert_eq!(report.state(), NtfsLogFileState::Incomplete);
    assert!(report.copies()[0].area().is_ok());
    let error = report.copies()[1].area().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Io);
    assert!(error.source.is_some());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
struct CancelAfterRead {
    image: Image,
    cancellation: Cancellation,
}
impl ReadAt for CancelAfterRead {
    fn len(&self) -> u64 {
        self.image.len()
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.image.read_exact_at(offset, bytes)?;
        self.cancellation.cancel();
        Ok(())
    }
}
#[test]
fn cancellation_during_page_io_prevents_clean_publication() {
    let r = resources();
    let source = Arc::new(CancelAfterRead {
        image: Image::new(fixture(true)),
        cancellation: r.cancellation.clone(),
    });
    let report = inspect_logfile(source, limits(), &r).unwrap();
    assert_eq!(report.state(), NtfsLogFileState::Incomplete);
    assert!(report.copies().iter().any(|copy| {
        copy.area()
            .is_err_and(|error| error.kind == ErrorKind::Cancelled)
    }));
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

struct ChangeLength(Image);
impl ReadAt for ChangeLength {
    fn len(&self) -> u64 {
        self.0.len()
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(offset, bytes)?;
        self.0.length.fetch_sub(512, Ordering::Relaxed);
        Ok(())
    }
}
#[test]
fn source_length_change_invalidates_even_matching_restart_evidence() {
    let r = resources();
    let report = inspect_logfile(
        Arc::new(ChangeLength(Image::new(fixture(true)))),
        limits(),
        &r,
    )
    .unwrap();
    assert_eq!(report.state(), NtfsLogFileState::Incomplete);
    assert_eq!(report.source_error().unwrap().kind, ErrorKind::StalePlan);
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
struct RestartOnly(Image);
impl ReadAt for RestartOnly {
    fn len(&self) -> u64 {
        self.0.len()
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        if offset + bytes.len() as u64 > 2 * PAGE as u64 {
            return Err(io::Error::other(
                "restart inspection reached log record area",
            ));
        }
        self.0.read_exact_at(offset, bytes)
    }
}
#[test]
fn restart_inspection_does_not_claim_or_read_transaction_record_pages() {
    let r = resources();
    let report = inspect_logfile(
        Arc::new(RestartOnly(Image::new(fixture(true)))),
        limits(),
        &r,
    )
    .unwrap();
    assert_eq!(report.state(), NtfsLogFileState::CleanFlagObserved);
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn malformed_copy_dominates_unsupported_copy_in_both_orders() {
    for unsupported_copy in 0..2 {
        let malformed_copy = 1 - unsupported_copy;
        let mut bytes = fixture(true);
        w(&mut bytes, unsupported_copy * PAGE + 28, 2);
        bytes[malformed_copy * PAGE + 510] ^= 1;
        let r = resources();
        let report = inspect_logfile(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
        assert_eq!(report.state(), NtfsLogFileState::Incomplete);
        assert_eq!(
            report.copies()[unsupported_copy].area().unwrap_err().kind,
            ErrorKind::Unsupported
        );
        assert_eq!(
            report.copies()[malformed_copy].area().unwrap_err().kind,
            ErrorKind::InvalidData
        );
        let header = report.copies()[unsupported_copy]
            .header()
            .expect("raw complete header");
        assert_eq!(header.version, (2, 1));
        assert_eq!(header.system_page_bytes, PAGE as u32);
        assert_eq!(header.log_page_bytes, PAGE as u32);
        assert_eq!(header.usa_offset, 32);
        assert_eq!(header.usa_count, 9);
        assert_eq!(header.area_offset, AREA as u16);
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn critical_restart_fields_stay_in_first_transfer_sector_and_log_window_has_native_minimum() {
    for mutation in 0..3 {
        let mut bytes = fixture(true);
        match mutation {
            0 => {
                let area = bytes[AREA..AREA + 224].to_vec();
                bytes[512..512 + 224].copy_from_slice(&area);
                w(&mut bytes, 24, 512);
            }
            1 => {
                let client = bytes[CLIENT..CLIENT + 160].to_vec();
                bytes[AREA + 456..AREA + 456 + 160].copy_from_slice(&client);
                w(&mut bytes, AREA + 22, 456);
                w(&mut bytes, AREA + 20, 616);
            }
            _ => {
                q(&mut bytes, AREA + 24, (4 * PAGE) as u64);
                d(&mut bytes, AREA + 16, 52);
            }
        }
        let r = resources();
        let report = inspect_logfile(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
        assert_eq!(
            report.copies()[0].area().unwrap_err().kind,
            ErrorKind::InvalidData,
            "mutation {mutation}"
        );
        assert_eq!(report.state(), NtfsLogFileState::Incomplete);
        assert!(report.copies()[1].area().is_ok());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}

#[path = "fixtures/ntfs_clean.rs"]
mod ntfs_clean;
fn read_limits() -> partmgr::fs_ntfs::NtfsReadLimits {
    partmgr::fs_ntfs::NtfsReadLimits {
        attributes: 32,
        runs: 64,
        names: 8,
    }
}
fn stream_limits() -> partmgr::fs_ntfs::NtfsStreamLimits {
    partmgr::fs_ntfs::NtfsStreamLimits {
        extension_records: 8,
        list_entries: 64,
        list_bytes: 4096,
        attributes: 32,
        runs: 64,
        work: 1_000_000,
    }
}
fn volume_fixture(mode: usize, dirty: bool) -> Vec<u8> {
    use ntfs_clean::{name_value, nonresident, put, resident};
    let mut bytes = ntfs_clean::ntfs_audit_seed();
    let log_bytes = 400 * 512;
    if mode != 1 {
        let data = nonresident(
            &[0x22, 0x90, 1, 0, 2, 0],
            400,
            log_bytes,
            if mode == 3 { log_bytes - 1 } else { log_bytes },
            mode == 2,
        );
        let mut data = data;
        if mode == 2 {
            q(&mut data, 64, log_bytes);
        }
        put(
            &mut bytes,
            2,
            &[resident(0x30, &name_value("$LogFile", 5), 2), data],
            false,
            1,
        );
    }
    let mut page1 = restart_page(true, 0xa55a);
    let mut page2 = restart_page(true, 0x7e21);
    for page in [&mut page1, &mut page2] {
        q(page, AREA + 24, log_bytes);
        d(page, AREA + 16, 49);
    }
    bytes[512 * 512..512 * 512 + PAGE].copy_from_slice(&page1);
    bytes[512 * 512 + PAGE..512 * 512 + 2 * PAGE].copy_from_slice(&page2);
    if dirty {
        let flags =
            2048 + 3 * 1024 + 56 + resident(0x30, &name_value("$Volume", 5), 2).len() + 24 + 10;
        w(&mut bytes, flags, 1);
    }
    let mirror = bytes[2048..6144].to_vec();
    bytes[500 * 512..508 * 512].copy_from_slice(&mirror);
    bytes
}
#[test]
fn volume_helper_resolves_native_logfile_owner_and_preserves_independent_volume_flags() {
    use partmgr::fs_ntfs_logfile::inspect_ntfs_logfile;
    for dirty in [false, true] {
        let r = resources();
        let inspected = inspect_ntfs_logfile(
            Arc::new(Image::new(volume_fixture(0, dirty))),
            read_limits(),
            stream_limits(),
            limits(),
            &r,
        )
        .unwrap();
        assert_eq!(
            u64::from_le_bytes(inspected.owner.native.as_slice().try_into().unwrap()),
            2
        );
        assert_eq!(inspected.owner.generation, 7);
        assert_eq!(inspected.volume_flags, u16::from(dirty));
        assert_eq!(
            inspected.report.state(),
            NtfsLogFileState::CleanFlagObserved
        );
        assert!(!inspected.report.transaction_analysis_complete());
        assert_eq!(inspected.report.source_bytes(), 400 * 512);
        drop(inspected);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn volume_helper_rejects_resident_sparse_and_uninitialized_logfile_streams() {
    use partmgr::fs_ntfs_logfile::inspect_ntfs_logfile;
    for mode in 1..4 {
        let r = resources();
        let failure = inspect_ntfs_logfile(
            Arc::new(Image::new(volume_fixture(mode, false))),
            read_limits(),
            stream_limits(),
            limits(),
            &r,
        )
        .err()
        .unwrap();
        assert_eq!(
            failure.kind,
            ErrorKind::Unsupported,
            "mode {mode}: {failure:?}"
        );
        assert_eq!(r.memory.used(), 0);
    }
}

struct EmbeddedRestartFailure(Image);
impl ReadAt for EmbeddedRestartFailure {
    fn len(&self) -> u64 {
        self.0.len()
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        if offset == PAGE as u64 {
            return Err(io::Error::other(partmgr::fs_core::Error::new(
                ErrorKind::Unsupported,
                "injected restart backend failure",
            )));
        }
        self.0.read_exact_at(offset, bytes)
    }
}
#[test]
fn structured_unsupported_backend_read_is_incomplete_evidence_not_format_exclusion() {
    let r = resources();
    let report = inspect_logfile(
        Arc::new(EmbeddedRestartFailure(Image::new(fixture(true)))),
        limits(),
        &r,
    )
    .unwrap();
    assert_eq!(report.state(), NtfsLogFileState::Incomplete);
    assert!(report.copies()[0].area().is_ok());
    assert!(!report.copies()[1].read_complete());
    assert_eq!(report.copies()[1].kind(), NtfsRestartPageKind::Unknown);
    let error = report.copies()[1].area().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Unsupported);
    let cause = error
        .source
        .as_ref()
        .unwrap()
        .get_ref()
        .unwrap()
        .downcast_ref::<partmgr::fs_core::Error>()
        .unwrap();
    assert_eq!(cause.context, "injected restart backend failure");
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn volume_page_inventory_uses_exact_system_owner_and_keeps_erased_slots_explicit() {
    use partmgr::fs_ntfs_logfile::{
        NtfsLogPageKind, NtfsLogPageLimits, NtfsLogPageRole, inspect_ntfs_logfile_pages,
    };
    for dirty in [false, true] {
        let r = resources();
        let inspected = inspect_ntfs_logfile_pages(
            Arc::new(Image::new(volume_fixture(0, dirty))),
            read_limits(),
            stream_limits(),
            limits(),
            NtfsLogPageLimits {
                pages: 64,
                retained_bytes: 64 * PAGE,
                work: 10000,
            },
            &r,
        )
        .unwrap();
        assert_eq!(
            u64::from_le_bytes(inspected.owner.native.as_slice().try_into().unwrap()),
            2
        );
        assert_eq!(inspected.owner.generation, 7);
        assert_eq!(inspected.volume_flags, u16::from(dirty));
        let report = &inspected.report;
        assert!(report.scan_complete());
        assert!(report.stopping_error().is_none());
        assert_eq!(
            report.restart().state(),
            NtfsLogFileState::CleanFlagObserved
        );
        assert_eq!(report.restart().source_bytes(), 400 * 512);
        assert_eq!(report.pages().len(), 48);
        assert_eq!(report.retained_bytes(), 48 * PAGE);
        assert!(!report.active_window_complete());
        assert!(!report.transaction_analysis_complete());
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
            assert!(page.read_complete());
            assert_eq!(page.kind(), NtfsLogPageKind::UninitializedZero);
            assert!(page.header().is_none());
            assert_eq!(page.error().unwrap().kind, ErrorKind::Unsupported);
        }
        drop(inspected);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn volume_page_inventory_rejects_excluded_native_logstream_forms_before_scan() {
    use partmgr::fs_ntfs_logfile::{NtfsLogPageLimits, inspect_ntfs_logfile_pages};
    for mode in 1..4 {
        let r = resources();
        let error = inspect_ntfs_logfile_pages(
            Arc::new(Image::new(volume_fixture(mode, false))),
            read_limits(),
            stream_limits(),
            limits(),
            NtfsLogPageLimits {
                pages: 64,
                retained_bytes: 64 * PAGE,
                work: 10000,
            },
            &r,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind, ErrorKind::Unsupported, "mode {mode}: {error:?}");
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn exact_version_two_zero_restart_uses_the_historical_160_byte_client_layout() {
    for clean in [false, true] {
        let mut bytes = fixture(clean);
        for offset in [0, PAGE] {
            w(&mut bytes, offset + 26, 0);
            w(&mut bytes, offset + 28, 2);
        }
        let expected = bytes.clone();
        let r = resources();
        let report = inspect_logfile(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
        assert_eq!(
            report.state(),
            if clean {
                NtfsLogFileState::CleanFlagObserved
            } else {
                NtfsLogFileState::RecoveryRequired
            }
        );
        assert!(!report.copies_disagree());
        assert!(!report.transaction_analysis_complete());
        for (index, copy) in report.copies().iter().enumerate() {
            let area = copy.area().unwrap();
            assert_eq!(area.version, (2, 0));
            assert_eq!(area.client_count, 1);
            assert_eq!(area.in_use_head, 0);
            assert_eq!(area.file_bytes, LENGTH as u64);
            assert_eq!(copy.raw(), &expected[index * PAGE..(index + 1) * PAGE]);
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
    // Client offset 64 plus historical client size 160 requires all 224 bytes.
    let mut bytes = fixture(true);
    for offset in [0, PAGE] {
        w(&mut bytes, offset + 26, 0);
        w(&mut bytes, offset + 28, 2);
        w(&mut bytes, offset + AREA + 20, 223);
    }
    let r = resources();
    let report = inspect_logfile(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
    assert_eq!(report.state(), NtfsLogFileState::Incomplete);
    assert!(
        report
            .copies()
            .iter()
            .all(|copy| copy.area().as_ref().unwrap_err().kind == ErrorKind::InvalidData)
    );
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn unknown_two_one_and_three_zero_restart_versions_remain_unsupported() {
    for (major, minor) in [(2, 1), (3, 0)] {
        let mut bytes = fixture(true);
        for offset in [0, PAGE] {
            w(&mut bytes, offset + 26, minor);
            w(&mut bytes, offset + 28, major);
        }
        let r = resources();
        let report = inspect_logfile(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
        assert_eq!(report.state(), NtfsLogFileState::Unsupported);
        for copy in report.copies() {
            assert_eq!(copy.header().unwrap().version, (major, minor));
            assert_eq!(
                copy.area().as_ref().unwrap_err().kind,
                ErrorKind::Unsupported
            );
        }
        assert!(!report.transaction_analysis_complete());
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn divergent_version_two_zero_copies_preserve_decoded_ambiguity() {
    let mut bytes = fixture(true);
    for offset in [0, PAGE] {
        w(&mut bytes, offset + 26, 0);
        w(&mut bytes, offset + 28, 2);
    }
    q(&mut bytes, PAGE + AREA, 0x12345678);
    let r = resources();
    let report = inspect_logfile(Arc::new(Image::new(bytes)), limits(), &r).unwrap();
    assert_eq!(report.state(), NtfsLogFileState::Incomplete);
    assert!(report.copies_disagree());
    assert!(report.copies().iter().all(|copy| copy.area().is_ok()));
    assert_eq!(report.copies()[0].area().unwrap().current_lsn, 0);
    assert_eq!(report.copies()[1].area().unwrap().current_lsn, 0x12345678);
    assert!(!report.transaction_analysis_complete());
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn version_two_zero_pages_are_inventoried_but_record_addresses_exclude_fast_slots() {
    use partmgr::fs_ntfs_logfile::{
        NtfsLogPageLimits, NtfsLogRecordLimits, inspect_logfile_pages, inspect_logfile_record,
    };
    let mut bytes = fixture(true);
    for offset in [0, PAGE] {
        w(&mut bytes, offset + 26, 0);
        w(&mut bytes, offset + 28, 2);
    }
    let source = Arc::new(Image::new(bytes));
    let r = resources();
    let pages = inspect_logfile_pages(
        source.clone(),
        limits(),
        NtfsLogPageLimits {
            pages: 64,
            retained_bytes: LENGTH,
            work: 10000,
        },
        &r,
    )
    .unwrap();
    assert_eq!(source.reads.load(Ordering::Relaxed), 64);
    assert_eq!(pages.restart().state(), NtfsLogFileState::CleanFlagObserved);
    assert!(pages.scan_complete());
    assert_eq!(pages.pages().len(), 62);
    assert!(pages.stopping_error().is_none());
    assert!(!pages.active_window_complete());
    assert!(!pages.transaction_analysis_complete());
    drop(pages);
    assert_eq!(r.memory.used(), 0);
    source.fail.store((2 * PAGE) as u64, Ordering::Relaxed);
    let record = inspect_logfile_record(
        source.clone(),
        limits(),
        NtfsLogRecordLimits {
            pages: 8,
            payload_bytes: 4096,
            work: 10000,
        },
        (7 << 16) | ((4 * PAGE + 64) as u64 / 8),
        &r,
    )
    .unwrap();
    assert_eq!(source.reads.load(Ordering::Relaxed), 66);
    assert_eq!(
        record.restart().state(),
        NtfsLogFileState::CleanFlagObserved
    );
    assert!(!record.complete());
    assert!(record.pages().is_empty());
    assert!(record.payload().is_none());
    assert_eq!(
        record.stopping_error().unwrap().kind,
        ErrorKind::InvalidData
    );
    assert!(!record.active_window_complete());
    assert!(!record.transaction_analysis_complete());
    drop(record);
    assert_eq!(r.memory.used(), 0);
}

// Modeled native-volume wrapper regression: record 2 is resolved through the
// existing independent NTFS volume fixture. This is not Windows crash evidence.
#[derive(Clone, Copy)]
enum FinalVolumeLenAction {
    Observe,
    Cancel,
    CancelAndChangeLength,
}
struct FinalVolumeLen {
    image: Image,
    calls: AtomicU64,
    final_call: u64,
    fired: std::sync::atomic::AtomicBool,
    action: FinalVolumeLenAction,
    cancellation: Cancellation,
}
impl FinalVolumeLen {
    fn new(
        bytes: Vec<u8>,
        final_call: u64,
        action: FinalVolumeLenAction,
        cancellation: Cancellation,
    ) -> Self {
        Self {
            image: Image::new(bytes),
            calls: AtomicU64::new(0),
            final_call,
            fired: std::sync::atomic::AtomicBool::new(false),
            action,
            cancellation,
        }
    }
}
impl ReadAt for FinalVolumeLen {
    fn len(&self) -> u64 {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let original_length = self.image.len();
        if self.final_call != 0 && call == self.final_call {
            self.fired.store(true, Ordering::SeqCst);
            match self.action {
                FinalVolumeLenAction::Observe => {}
                FinalVolumeLenAction::Cancel => self.cancellation.cancel(),
                FinalVolumeLenAction::CancelAndChangeLength => {
                    self.cancellation.cancel();
                    return original_length + 512;
                }
            }
        }
        original_length
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.image.read_exact_at(at, out)
    }
}
#[test]
fn modeled_native_volume_discovery_seed_withholds_final_length_callback_cancellation() {
    use partmgr::fs_ntfs_logfile::{
        NtfsLogDiscoverySeedLimits, NtfsLogRestartOrdering, inspect_ntfs_logfile_discovery_seed,
    };
    let seed_limits = NtfsLogDiscoverySeedLimits {
        restart: limits(),
        pages: 65,
        work: 20_000,
    };
    let ordering = NtfsLogRestartOrdering::NumericWithoutRollover;
    let bytes = volume_fixture(0, false);
    // Learn the precise last original.len() callback from a successful identical
    // wrapper run. There are no guessed read/length counts or earlier triggers.
    let baseline_resources = resources();
    let baseline = Arc::new(FinalVolumeLen::new(
        bytes.clone(),
        0,
        FinalVolumeLenAction::Observe,
        baseline_resources.cancellation.clone(),
    ));
    let success = inspect_ntfs_logfile_discovery_seed(
        baseline.clone(),
        read_limits(),
        stream_limits(),
        seed_limits,
        ordering,
        &baseline_resources,
    )
    .unwrap();
    assert!(success.report.seed().is_some());
    assert!(success.report.stopping_error().is_none());
    assert_eq!(
        u64::from_le_bytes(success.owner.native.as_slice().try_into().unwrap()),
        2
    );
    let final_call = baseline.calls.load(Ordering::SeqCst);
    assert!(final_call > 1);
    drop(success);
    assert_eq!(baseline_resources.memory.used(), 0);
    for (action, expected) in [
        (FinalVolumeLenAction::Cancel, ErrorKind::Cancelled),
        (
            FinalVolumeLenAction::CancelAndChangeLength,
            ErrorKind::StalePlan,
        ),
    ] {
        let r = resources();
        let source = Arc::new(FinalVolumeLen::new(
            bytes.clone(),
            final_call,
            action,
            r.cancellation.clone(),
        ));
        let observed = inspect_ntfs_logfile_discovery_seed(
            source.clone(),
            read_limits(),
            stream_limits(),
            seed_limits,
            ordering,
            &r,
        )
        .unwrap();
        assert!(
            source.fired.load(Ordering::SeqCst),
            "final volume callback not reached"
        );
        assert_eq!(
            source.calls.load(Ordering::SeqCst),
            final_call,
            "callback was not precisely the final original.len check"
        );
        assert!(
            observed.report.selection().selected_context().is_some(),
            "restart selection must survive the later volume guard failure"
        );
        assert!(observed.report.seed().is_none());
        assert_eq!(observed.report.source_error().unwrap().kind, expected);
        assert_eq!(observed.report.stopping_error().unwrap().kind, expected);
        assert!(r.cancellation.check().is_err());
        assert!(!observed.report.active_window_complete());
        assert!(!observed.report.recovery_complete());
        drop(observed);
        assert_eq!(r.memory.used(), 0);
    }
}

#[test]
fn native_analysis_context_uses_source_geometry_owner_and_exact_guards() {
    use partmgr::fs_ntfs_logfile::{
        NtfsLogNativeContextLimits, inspect_ntfs_log_native_analysis_context,
    };
    for dirty in [false, true] {
        let r = resources();
        let source = Arc::new(Image::new(volume_fixture(0, dirty)));
        let context = inspect_ntfs_log_native_analysis_context(
            source.clone(),
            read_limits(),
            stream_limits(),
            NtfsLogNativeContextLimits {
                reads: 256,
                bytes: 262144,
                work: 1_000_000,
            },
            &r,
        )
        .unwrap();
        assert_eq!(context.geometry().cluster_bytes(), 512);
        assert_eq!(context.geometry().record_bytes(), 1024);
        assert_eq!(context.volume_flags(), u16::from(dirty));
        assert_eq!(context.owner().native, 2u64.to_le_bytes());
        assert_eq!(context.owner().generation, 7);
        assert_eq!(context.logfile_source().len(), 400 * 512);
        assert!(context.source_observations() > 3);
        assert!(!context.active_window_complete());
        assert!(!context.recovery_complete());
        context.check_source(&r).unwrap();
        source.length.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(
            context.check_source(&r).unwrap_err().kind,
            ErrorKind::StalePlan
        );
        drop(context);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn native_context_binds_ephemeral_consumed_boot_bytes_even_with_identical_geometry() {
    use partmgr::fs_ntfs_logfile::{
        NtfsLogNativeContextLimits, inspect_ntfs_log_native_analysis_context,
    };
    struct EphemeralBoot {
        bytes: Vec<u8>,
        boot_reads: AtomicU64,
    }
    impl ReadAt for EphemeralBoot {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            let start = offset as usize;
            out.copy_from_slice(
                self.bytes
                    .get(start..start + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            if offset == 0
                && out.len() >= 512
                && self.boot_reads.fetch_add(1, Ordering::Relaxed) == 0
            {
                out[80] ^= 1; // Volume serial byte; all admitted geometry is unchanged.
            }
            Ok(())
        }
    }
    let r = resources();
    let source = Arc::new(EphemeralBoot {
        bytes: volume_fixture(0, false),
        boot_reads: AtomicU64::new(0),
    });
    let result = inspect_ntfs_log_native_analysis_context(
        source,
        read_limits(),
        stream_limits(),
        NtfsLogNativeContextLimits {
            reads: 256,
            bytes: 262144,
            work: 1_000_000,
        },
        &r,
    );
    match result {
        Err(error) => assert_eq!(error.kind, ErrorKind::StalePlan),
        Ok(_) => panic!("unbound consumed boot bytes accepted"),
    }
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn native_context_observes_final_len_and_capture_range_callback_cancellation() {
    use partmgr::fs_ntfs_logfile::{
        NtfsLogNativeContextLimits, inspect_ntfs_log_native_analysis_context,
    };
    struct CallbackVolume {
        bytes: Vec<u8>,
        cancellation: Cancellation,
        lengths: AtomicU64,
        reads: AtomicU64,
        first_read_len: AtomicU64,
        cancel_at: u64,
    }
    impl ReadAt for CallbackVolume {
        fn len(&self) -> u64 {
            let call = self.lengths.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.cancel_at {
                self.cancellation.cancel();
            }
            self.bytes.len() as u64
        }
        fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
                self.first_read_len
                    .store(self.lengths.load(Ordering::SeqCst), Ordering::SeqCst);
            }
            let start = offset as usize;
            out.copy_from_slice(
                self.bytes
                    .get(start..start + out.len())
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }
    }
    let make = |r: &Resources, cancel_at| {
        Arc::new(CallbackVolume {
            bytes: volume_fixture(0, false),
            cancellation: r.cancellation.clone(),
            lengths: AtomicU64::new(0),
            reads: AtomicU64::new(0),
            first_read_len: AtomicU64::new(0),
            cancel_at,
        })
    };
    let limits = NtfsLogNativeContextLimits {
        reads: 256,
        bytes: 262144,
        work: 1_000_000,
    };
    let r = resources();
    let baseline = make(&r, u64::MAX);
    let context = inspect_ntfs_log_native_analysis_context(
        baseline.clone(),
        read_limits(),
        stream_limits(),
        limits,
        &r,
    )
    .unwrap();
    let final_len_call = baseline.lengths.load(Ordering::SeqCst);
    let first_capture_range = baseline.first_read_len.load(Ordering::SeqCst);
    assert!(final_len_call > first_capture_range);
    assert!(first_capture_range > 0);
    drop(context);
    assert_eq!(r.memory.used(), 0);
    let r = resources();
    let source = make(&r, final_len_call);
    let result = inspect_ntfs_log_native_analysis_context(
        source.clone(),
        read_limits(),
        stream_limits(),
        limits,
        &r,
    );
    match result {
        Err(e) => assert_eq!(e.kind, ErrorKind::Cancelled),
        Ok(_) => panic!("final source len cancellation accepted"),
    }
    assert_eq!(source.lengths.load(Ordering::SeqCst), final_len_call);
    assert_eq!(r.memory.used(), 0);
    let r = resources();
    let source = make(&r, first_capture_range);
    let result = inspect_ntfs_log_native_analysis_context(
        source.clone(),
        read_limits(),
        stream_limits(),
        limits,
        &r,
    );
    assert!(result.is_err());
    assert_eq!(
        r.cancellation.check().unwrap_err().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(
        source.reads.load(Ordering::SeqCst),
        0,
        "range len callback must cancel before source I/O"
    );
    assert_eq!(r.memory.used(), 0);
}
