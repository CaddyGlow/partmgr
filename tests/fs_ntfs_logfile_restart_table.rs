#![cfg(feature = "std")]
//! Independently authored restart-table dumps within source-bound client records.
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ntfs_logfile::{
        NtfsLogFileLimits, NtfsLogRecordLimits, NtfsLogRecordReport, NtfsLogRestartTableKind,
        NtfsLogRestartTableLimits, inspect_logfile_record, inspect_ntfs_log_client_record,
        inspect_ntfs_log_restart_table,
    },
    io,
};
use std::sync::Arc;
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
        let original = u16::from_le_bytes([b[at], b[at + 1]]);
        w(b, usa + sector * 2, original);
        w(b, at, marker);
    }
}
struct Image(Vec<u8>);
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let at = usize::try_from(offset).map_err(io::Error::other)?;
        let end = at
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(self.0.get(at..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
fn resources() -> Resources {
    Resources {
        memory: Budget::new(1 << 20),
        cancellation: Cancellation::default(),
    }
}
fn fixture(payload: &[u8], lfs_major: u16, record_type: u32, torn: bool) -> (Vec<u8>, u64) {
    let ordinary_page = if lfs_major == 1 { 4 } else { 34 };
    let query = (7u64 << 16) | ((ordinary_page * PAGE + 64) as u64 / 8);
    let mut bytes = vec![0xff; LENGTH];
    for index in 0..2 {
        let mut page = vec![0; PAGE];
        page[..4].copy_from_slice(b"RSTR");
        w(&mut page, 4, 32);
        w(&mut page, 6, 9);
        d(&mut page, 16, PAGE as u32);
        d(&mut page, 20, PAGE as u32);
        w(&mut page, 24, 56);
        w(&mut page, 26, if lfs_major == 1 { 1 } else { 0 });
        w(&mut page, 28, lfs_major);
        q(&mut page, 56, query);
        w(&mut page, 64, 1);
        w(&mut page, 66, u16::MAX);
        w(&mut page, 68, 0);
        d(&mut page, 72, 48);
        w(&mut page, 76, 224);
        w(&mut page, 78, 64);
        q(&mut page, 80, LENGTH as u64);
        w(&mut page, 92, 48);
        w(&mut page, 94, 64);
        w(&mut page, 136, u16::MAX);
        w(&mut page, 138, u16::MAX);
        w(&mut page, 140, 9);
        d(&mut page, 148, 8);
        page[152..160].copy_from_slice(b"N\0T\0F\0S\0");
        protect(&mut page, 32, 0xab00 + index as u16);
        bytes[index * PAGE..(index + 1) * PAGE].copy_from_slice(&page);
    }
    let mut page = vec![0; PAGE];
    page[..4].copy_from_slice(b"RCRD");
    w(&mut page, 4, 40);
    w(&mut page, 6, 9);
    q(&mut page, 8, query);
    d(&mut page, 16, 1);
    w(&mut page, 20, 1);
    w(&mut page, 22, 1);
    w(
        &mut page,
        24,
        (112 + payload.len()).next_multiple_of(8) as u16,
    );
    q(&mut page, 32, query);
    q(&mut page, 64, query);
    d(&mut page, 88, payload.len() as u32);
    w(&mut page, 92, 9);
    w(&mut page, 94, 0);
    d(&mut page, 96, record_type);
    page[112..112 + payload.len()].copy_from_slice(payload);
    protect(&mut page, 40, 0xf1f2);
    if torn {
        page[510] ^= 1;
    }
    bytes[ordinary_page * PAGE..(ordinary_page + 1) * PAGE].copy_from_slice(&page);
    (bytes, query)
}
fn record(
    payload: &[u8],
    lfs_major: u16,
    record_type: u32,
    torn: bool,
    r: &Resources,
) -> NtfsLogRecordReport {
    let (bytes, lsn) = fixture(payload, lfs_major, record_type, torn);
    inspect_logfile_record(
        Arc::new(Image(bytes)),
        NtfsLogFileLimits {
            restart_page_bytes: PAGE,
            clients: 1,
            work: 10000,
        },
        NtfsLogRecordLimits {
            pages: 8,
            payload_bytes: 4096,
            work: 10000,
        },
        lsn,
        r,
    )
    .unwrap()
}

fn table_limits() -> NtfsLogRestartTableLimits {
    NtfsLogRestartTableLimits {
        entries: 32,
        bytes: 4096,
        work: 10000,
    }
}
fn table_dump(table: &[u8], operation: u16) -> Vec<u8> {
    let mut payload = vec![0; 40 + table.len()];
    w(&mut payload, 0, operation);
    w(&mut payload, 4, 40);
    w(&mut payload, 6, table.len() as u16);
    payload[40..].copy_from_slice(table);
    payload
}
fn table_fixture() -> Vec<u8> {
    let mut b = vec![0x6d; 96];
    w(&mut b, 0, 16);
    w(&mut b, 2, 4);
    w(&mut b, 4, 2);
    b[6..12].copy_from_slice(&[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]);
    d(&mut b, 12, 0x12345678);
    d(&mut b, 16, 40);
    d(&mut b, 20, 72);
    d(&mut b, 24, u32::MAX);
    d(&mut b, 40, 72);
    d(&mut b, 56, u32::MAX);
    d(&mut b, 72, 0);
    b
}
#[test]
fn typed_dump_tables_borrow_exact_slots_free_chain_reserved_and_trailing_bytes() {
    let raw = table_fixture();
    for (operation, kind) in [
        (29, NtfsLogRestartTableKind::OpenAttributes),
        (31, NtfsLogRestartTableKind::DirtyPages),
        (32, NtfsLogRestartTableKind::Transactions),
    ] {
        let r = resources();
        let report = record(&table_dump(&raw, operation), 2, 1, false, &r);
        let charged = r.memory.used();
        {
            let client = inspect_ntfs_log_client_record(&report).unwrap();
            let view = inspect_ntfs_log_restart_table(&client, table_limits(), &r).unwrap();
            assert_eq!(view.kind(), kind);
            assert_eq!(view.entry_bytes, 16);
            assert_eq!(view.capacity, 4);
            assert_eq!(view.allocated, 2);
            assert_eq!(view.free_goal, 0x12345678);
            assert_eq!(view.first_free, 40);
            assert_eq!(view.last_free, 72);
            assert_eq!(view.raw(), raw);
            assert_eq!(view.table_bytes(), &raw[..88]);
            assert_eq!(view.trailing_bytes(), &raw[88..]);
            assert_eq!(view.reserved_bytes(), &raw[6..12]);
            assert!(std::ptr::eq(view.raw().as_ptr(), client.redo().as_ptr()));
            for index in 0..4 {
                let entry = view.entry(index).unwrap();
                let offset = 24 + 16 * index;
                assert_eq!(entry.index, index);
                assert_eq!(entry.offset, offset);
                assert_eq!(entry.raw(), &raw[offset..offset + 16]);
                assert_eq!(entry.allocated(), index % 2 == 0);
                assert_eq!(
                    entry.link(),
                    u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap())
                );
            }
            assert!(view.entry(4).is_none());
            assert!(view.entry(usize::MAX).is_none());
            assert!(!view.entry_semantics_supported());
            assert!(view.work() > 0);
            assert_eq!(r.memory.used(), charged);
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn empty_fully_allocated_and_fully_free_tables_have_distinct_valid_head_rules() {
    for mode in 0..3 {
        let capacity = if mode == 0 { 0 } else { 3 };
        let mut raw = vec![0; 24 + capacity * 4];
        w(&mut raw, 0, 4);
        w(&mut raw, 2, capacity as u16);
        if mode == 1 {
            w(&mut raw, 4, 3);
            for index in 0..3 {
                d(&mut raw, 24 + index * 4, u32::MAX);
            }
        }
        if mode == 2 {
            d(&mut raw, 16, 24);
            d(&mut raw, 20, 32);
            d(&mut raw, 24, 28);
            d(&mut raw, 28, 32);
            d(&mut raw, 32, 0);
        }
        let r = resources();
        let report = record(&table_dump(&raw, 29), 1, 1, false, &r);
        {
            let client = inspect_ntfs_log_client_record(&report).unwrap();
            let view = inspect_ntfs_log_restart_table(&client, table_limits(), &r).unwrap();
            assert_eq!(usize::from(view.capacity), capacity);
            assert_eq!(view.allocated, if mode == 1 { 3 } else { 0 });
            assert_eq!(view.raw(), raw);
            for index in 0..capacity {
                assert_eq!(view.entry(index).unwrap().allocated(), mode == 1);
            }
            assert!(view.entry(capacity).is_none());
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn table_header_and_slot_extent_are_checked_before_lazy_entry_access() {
    for mode in 0..7 {
        let mut raw = table_fixture();
        match mode {
            0 => raw.truncate(23),
            1 => w(&mut raw, 0, 0),
            2 => w(&mut raw, 0, 3),
            3 => w(&mut raw, 2, u16::MAX),
            4 => w(&mut raw, 4, 5),
            5 => w(&mut raw, 4, 3),
            _ => raw.truncate(87),
        }
        let r = resources();
        let report = record(&table_dump(&raw, 29), 2, 1, false, &r);
        let client = inspect_ntfs_log_client_record(&report).unwrap();
        let charged = r.memory.used();
        assert_eq!(
            inspect_ntfs_log_restart_table(
                &client,
                NtfsLogRestartTableLimits {
                    entries: usize::MAX,
                    ..table_limits()
                },
                &r
            )
            .err()
            .unwrap()
            .kind,
            ErrorKind::InvalidData,
            "mode {mode}"
        );
        assert_eq!(r.memory.used(), charged);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn malformed_heads_links_cycles_and_incomplete_free_membership_are_rejected() {
    for mode in 0..11 {
        let mut raw = table_fixture();
        match mode {
            0 => d(&mut raw, 16, 25),
            1 => d(&mut raw, 16, 88),
            2 => d(&mut raw, 16, 24),
            3 => d(&mut raw, 20, 25),
            4 => d(&mut raw, 20, 88),
            5 => d(&mut raw, 40, 25),
            6 => d(&mut raw, 40, 88),
            7 => d(&mut raw, 72, 40),
            8 => d(&mut raw, 40, 24),
            9 => {
                d(&mut raw, 40, 0);
                d(&mut raw, 20, 40);
            }
            _ => {
                d(&mut raw, 16, 0);
                d(&mut raw, 20, 0);
            }
        }
        let r = resources();
        let report = record(&table_dump(&raw, 31), 2, 1, false, &r);
        let client = inspect_ntfs_log_client_record(&report).unwrap();
        let charged = r.memory.used();
        assert_eq!(
            inspect_ntfs_log_restart_table(&client, table_limits(), &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::InvalidData,
            "mode {mode}"
        );
        assert_eq!(r.memory.used(), charged);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn dump_kind_is_derived_from_original_redo_opcode_not_editable_observation_fields() {
    for operation in [29, 30, 0xf00d] {
        let r = resources();
        let report = record(&table_dump(&table_fixture(), operation), 2, 1, false, &r);
        let mut client = inspect_ntfs_log_client_record(&report).unwrap();
        client.redo_operation = if operation == 29 { 30 } else { 29 };
        if operation == 29 {
            let view = inspect_ntfs_log_restart_table(&client, table_limits(), &r).unwrap();
            assert_eq!(view.kind(), NtfsLogRestartTableKind::OpenAttributes);
        } else {
            assert_eq!(
                inspect_ntfs_log_restart_table(&client, table_limits(), &r)
                    .err()
                    .unwrap()
                    .kind,
                ErrorKind::Unsupported
            );
        }
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
#[test]
fn table_inspection_has_independent_byte_entry_work_and_cancellation_limits_without_allocation() {
    let r = resources();
    let raw = table_fixture();
    let report = record(&table_dump(&raw, 32), 2, 1, false, &r);
    let client = inspect_ntfs_log_client_record(&report).unwrap();
    let charged = r.memory.used();
    for caps in [
        NtfsLogRestartTableLimits {
            bytes: raw.len() - 1,
            ..table_limits()
        },
        NtfsLogRestartTableLimits {
            entries: 3,
            ..table_limits()
        },
        NtfsLogRestartTableLimits {
            work: 0,
            ..table_limits()
        },
    ] {
        assert_eq!(
            inspect_ntfs_log_restart_table(&client, caps, &r)
                .err()
                .unwrap()
                .kind,
            ErrorKind::BudgetExhausted
        );
        assert_eq!(r.memory.used(), charged);
    }
    let no_memory = Resources {
        memory: Budget::new(0),
        cancellation: Cancellation::default(),
    };
    assert!(inspect_ntfs_log_restart_table(&client, table_limits(), &no_memory).is_ok());
    assert_eq!(no_memory.memory.used(), 0);
    no_memory.cancellation.cancel();
    assert_eq!(
        inspect_ntfs_log_restart_table(&client, table_limits(), &no_memory)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Cancelled
    );
    assert_eq!(r.memory.used(), charged);
    drop(report);
    assert_eq!(r.memory.used(), 0);
}

#[test]
fn mutable_table_observations_do_not_change_private_validated_entry_bounds() {
    let raw = table_fixture();
    let r = resources();
    let report = record(&table_dump(&raw, 29), 2, 1, false, &r);
    {
        let client = inspect_ntfs_log_client_record(&report).unwrap();
        let mut view = inspect_ntfs_log_restart_table(&client, table_limits(), &r).unwrap();
        view.capacity = u16::MAX;
        view.entry_bytes = u16::MAX;
        view.allocated = u16::MAX;
        assert_eq!(view.entry(3).unwrap().raw(), &raw[72..88]);
        assert!(view.entry(4).is_none());
        assert!(view.entry(usize::MAX).is_none());
        assert_eq!(view.table_bytes(), &raw[..88]);
        assert_eq!(view.trailing_bytes(), &raw[88..]);
        view.capacity = 0;
        view.entry_bytes = 0;
        assert_eq!(view.entry(0).unwrap().raw(), &raw[24..40]);
        assert!(view.entry(4).is_none());
    }
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn generic_slot_alignment_uses_entry_size_without_guessing_type_specific_word_padding() {
    let mut raw = vec![0; 34];
    w(&mut raw, 0, 5);
    w(&mut raw, 2, 2);
    d(&mut raw, 16, 24);
    d(&mut raw, 20, 29);
    d(&mut raw, 24, 29);
    d(&mut raw, 29, 0);
    let r = resources();
    let report = record(&table_dump(&raw, 31), 2, 1, false, &r);
    {
        let client = inspect_ntfs_log_client_record(&report).unwrap();
        let view = inspect_ntfs_log_restart_table(&client, table_limits(), &r).unwrap();
        assert_eq!(view.entry_bytes, 5);
        assert_eq!(view.entry(1).unwrap().offset, 29);
        assert_eq!(view.entry(1).unwrap().raw(), &raw[29..34]);
        assert!(!view.entry_semantics_supported());
    }
    drop(report);
    assert_eq!(r.memory.used(), 0);
}
