#![cfg(feature = "std")]
//! Explicit dirty Windows 2.0 restart observations, without recovery qualification.
use partmgr::{
    fs_core::{Budget, Cancellation, ErrorKind, Resources},
    fs_ntfs::{NtfsReadLimits, NtfsStreamLimits},
    fs_ntfs_logfile::{
        NtfsLogCheckpointDumpLimits, NtfsLogFileLimits, NtfsLogFileState, NtfsLogPageLimits,
        NtfsLogPageRole, NtfsLogRecordLimits, NtfsLogRecordQuery, NtfsLogRestartTableLimits,
        inspect_logfile, inspect_logfile_checkpoint_dumps, inspect_logfile_pages,
        inspect_logfile_record, inspect_logfile_record_in_restart, inspect_ntfs_client_restart,
        inspect_ntfs_log_client_record, inspect_ntfs_log_restart_table, inspect_ntfs_logfile,
        inspect_ntfs_logfile_checkpoint_dumps, inspect_ntfs_logfile_pages,
        inspect_ntfs_logfile_record, inspect_ntfs_logfile_record_in_restart,
    },
    io,
};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write,
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use virtdisk::ReadAt;

struct Stream {
    bytes: Vec<u8>,
    restart_only: bool,
    reads: AtomicU64,
}
impl ReadAt for Stream {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        if self.restart_only && offset >= 8192 {
            return Err(io::Error::other("2.0 gate forbids physical log slot reads"));
        }
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(
            self.bytes
                .get(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn restart_limits() -> NtfsLogFileLimits {
    NtfsLogFileLimits {
        restart_page_bytes: 4096,
        clients: 1,
        work: 1000,
    }
}
fn read_limits() -> NtfsReadLimits {
    NtfsReadLimits {
        attributes: 128,
        runs: 256,
        names: 64,
    }
}
fn stream_limits() -> NtfsStreamLimits {
    NtfsStreamLimits {
        extension_records: 128,
        list_entries: 2048,
        list_bytes: 1 << 20,
        attributes: 256,
        runs: 1024,
        work: 2 << 20,
    }
}
fn page_limits() -> NtfsLogPageLimits {
    NtfsLogPageLimits {
        pages: 4096,
        retained_bytes: 16 << 20,
        work: 100_000,
    }
}
fn record_limits() -> NtfsLogRecordLimits {
    NtfsLogRecordLimits {
        pages: 64,
        payload_bytes: 1 << 20,
        work: 2 << 20,
    }
}

#[test]
#[ignore = "requires exact dirty Windows pre-recovery stream, volume, acquisition receipt, compiled source root and fresh evidence destination"]
fn native_dirty_two_zero_restart_preserves_ambiguity_without_recovery_claim() {
    let required = |name| PathBuf::from(std::env::var_os(name).expect(name));
    let stream_path = required("PARTMGR_NTFS_DIRTY_LOGFILE_STREAM");
    let volume_path = required("PARTMGR_NTFS_DIRTY_LOGFILE_VOLUME");
    let receipt_path = required("PARTMGR_NTFS_DIRTY_LOGFILE_FIXTURE_RECEIPT");
    let source_root = required("PARTMGR_GATE_SOURCE_ROOT");
    let oracle_path = required("PARTMGR_NTFS_DIRTY_LOGFILE_PAGE_ORACLE");
    let record_oracle_path = required("PARTMGR_NTFS_DIRTY_LOGFILE_RECORD_ORACLE");
    let checkpoint_oracle_path = required("PARTMGR_NTFS_DIRTY_LOGFILE_CHECKPOINT_ORACLE");
    let table_oracle_path = required("PARTMGR_NTFS_DIRTY_LOGFILE_TABLE_ORACLE");
    let out = required("PARTMGR_NTFS_DIRTY_LOGFILE_EVIDENCE");
    fs::create_dir(&out).expect("fresh evidence directory required");
    macro_rules! source {
        ($name:literal) => {
            ($name, &include_bytes!(concat!("../", $name))[..])
        };
    }
    let sources: &[(&str, &[u8])] = &[
        source!("Cargo.toml"),
        source!("Cargo.lock"),
        source!("src/lib.rs"),
        source!("src/fs_core.rs"),
        source!("src/io.rs"),
        source!("src/platform.rs"),
        source!("src/fs_file.rs"),
        source!("src/storage.rs"),
        source!("src/fs_ntfs.rs"),
        source!("src/fs_ntfs_stream.rs"),
        source!("src/fs_ntfs_bootstrap.rs"),
        source!("src/fs_ntfs_compressed.rs"),
        source!("src/fs_ntfs_logfile.rs"),
        source!("src/fs_ntfs_logfile/pages.rs"),
        source!("src/fs_ntfs_logfile/record.rs"),
        source!("src/fs_ntfs_logfile/checkpoint.rs"),
        source!("src/fs_ntfs_logfile/client_record.rs"),
        source!("src/fs_ntfs_logfile/restart_table.rs"),
        source!("src/fs_ntfs_logfile/checkpoint_dumps.rs"),
        source!("src/fs_ntfs_logfile/table_entries.rs"),
        source!("tests/fs_ntfs_logfile_dirty_native.rs"),
        source!("integration/maintenance/logfile-dirty-page-oracle.py"),
        source!("integration/maintenance/logfile-dirty-record-oracle.py"),
        source!("integration/maintenance/logfile-dirty-checkpoint-oracle.py"),
        source!("integration/maintenance/logfile-dirty-table-oracle.py"),
    ];
    let check_sources = || {
        let mut manifest = String::new();
        for (name, baked) in sources {
            assert_eq!(
                Sha256::digest(fs::read(source_root.join(name)).unwrap()),
                Sha256::digest(baked),
                "compiled source mismatch: {name}"
            );
            writeln!(manifest, "{:x}  {name}", Sha256::digest(baked)).unwrap();
        }
        manifest
    };
    let source_start = check_sources();
    fs::write(out.join("source-start.sha256"), &source_start).unwrap();
    for (name, baked) in sources {
        let destination = out.join("compiled-source").join(name);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(destination, baked).unwrap();
    }
    let binary_path = std::env::current_exe().unwrap();
    let binary = fs::read(&binary_path).unwrap();
    let binary_hash = Sha256::digest(&binary);
    fs::write(out.join("gate-binary"), binary).unwrap();
    let stream = fs::read(&stream_path).expect("dirty native log stream required");
    let stream_hash = Sha256::digest(&stream);
    let volume = fs::read(&volume_path).expect("dirty native volume required");
    let volume_hash = Sha256::digest(&volume);
    let receipt = fs::read(&receipt_path).expect("pre-recovery acquisition receipt required");
    let receipt_hash = Sha256::digest(&receipt);
    let oracle = fs::read(&oracle_path).expect("independent dirty page oracle required");
    let oracle_hash = Sha256::digest(&oracle);
    let record_oracle =
        fs::read(&record_oracle_path).expect("independent dirty record oracle required");
    let record_oracle_hash = Sha256::digest(&record_oracle);
    let checkpoint_oracle =
        fs::read(&checkpoint_oracle_path).expect("independent checkpoint oracle required");
    let checkpoint_oracle_hash = Sha256::digest(&checkpoint_oracle);
    let table_oracle = fs::read(&table_oracle_path).expect("independent table oracle required");
    let table_oracle_hash = Sha256::digest(&table_oracle);
    let table_text = std::str::from_utf8(&table_oracle).unwrap();
    assert_eq!(
        table_text.lines().next().unwrap(),
        format!("# source_sha256={stream_hash:x}")
    );
    let table_rows: Vec<_> = table_text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(table_rows.len(), 6);
    fs::write(out.join("independent-table-oracle.tsv"), &table_oracle).unwrap();
    let checkpoint_oracle_text = std::str::from_utf8(&checkpoint_oracle).unwrap();
    assert_eq!(
        checkpoint_oracle_text.lines().next().unwrap(),
        format!("# source_sha256={stream_hash:x}")
    );
    let checkpoint_rows: Vec<_> = checkpoint_oracle_text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(checkpoint_rows.len(), 2);
    fs::write(
        out.join("independent-checkpoint-oracle.tsv"),
        &checkpoint_oracle,
    )
    .unwrap();
    let record_oracle_text = std::str::from_utf8(&record_oracle).unwrap();
    assert_eq!(
        record_oracle_text.lines().next().unwrap(),
        format!("# source_sha256={stream_hash:x}")
    );
    let record_rows: Vec<_> = record_oracle_text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(record_rows.len(), 2);
    fs::write(out.join("independent-record-oracle.tsv"), &record_oracle).unwrap();
    let oracle_text = std::str::from_utf8(&oracle).unwrap();
    assert_eq!(
        oracle_text.lines().next().unwrap(),
        format!("# source_sha256={stream_hash:x}")
    );
    fs::write(out.join("independent-page-oracle.tsv"), &oracle).unwrap();
    assert_eq!(
        format!("{stream_hash:x}"),
        "d027c26addbb038c896f493868d9da85a0b7a883933429bbcad11109496ec912"
    );
    assert_eq!(
        format!("{volume_hash:x}"),
        "e0ba3d1b1ca7b985a5632da57f404a70f6450ee8a4971ccd9d2e147c6cff687c"
    );
    assert_eq!(
        format!("{receipt_hash:x}"),
        "39cebc61a16eb3683a5ad29316daf6a89aed83ea8fc523089bf285c4c323846d"
    );
    fs::write(out.join("fixture-provenance-receipt"), receipt).unwrap();
    fs::write(out.join("command.txt"),format!("argv={:?}\nstream={stream_path:?}\nvolume={volume_path:?}\nreceipt={receipt_path:?}\nsource_root={source_root:?}\nevidence={out:?}\n",std::env::args_os().collect::<Vec<_>>())).unwrap();
    let r = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let direct_source = Arc::new(Stream {
        bytes: stream,
        restart_only: true,
        reads: AtomicU64::new(0),
    });
    let volume_source = Arc::new(Stream {
        bytes: volume,
        restart_only: false,
        reads: AtomicU64::new(0),
    });
    let report = inspect_logfile(direct_source.clone(), restart_limits(), &r).unwrap();
    assert_eq!(report.state(), NtfsLogFileState::Incomplete);
    assert!(report.copies_disagree());
    assert!(report.source_error().is_none());
    assert!(!report.transaction_analysis_complete());
    assert_eq!(direct_source.reads.load(Ordering::SeqCst), 2);
    let mut observations = String::new();
    for (index, copy) in report.copies().iter().enumerate() {
        assert!(copy.read_complete());
        assert_eq!(copy.header().unwrap().version, (2, 0));
        let area = copy.area().expect("native 2.0 restart must decode");
        assert_eq!(area.version, (2, 0));
        assert_eq!(area.flags, 0);
        assert_eq!(area.client_count, 1);
        assert_eq!(area.current_lsn, [4753128, 4839042][index]);
        fs::write(out.join(format!("restart-{index}.bin")), copy.raw()).unwrap();
        writeln!(
            observations,
            "copy={index} header={:?} area={area:?}",
            copy.header()
        )
        .unwrap();
    }
    let selected = inspect_ntfs_logfile(
        volume_source.clone(),
        read_limits(),
        stream_limits(),
        restart_limits(),
        &r,
    )
    .unwrap();
    assert_eq!(selected.owner.native, 2u64.to_le_bytes());
    assert_ne!(selected.owner.generation, 0);
    assert_eq!(selected.report.state(), NtfsLogFileState::Incomplete);
    assert!(selected.report.copies_disagree());
    assert!(selected.report.source_error().is_none());
    for (direct, native) in report.copies().iter().zip(selected.report.copies()) {
        assert_eq!(direct.raw(), native.raw());
        assert_eq!(direct.area().unwrap(), native.area().unwrap());
    }
    let page_source = Arc::new(Stream {
        bytes: direct_source.bytes.clone(),
        restart_only: false,
        reads: AtomicU64::new(0),
    });
    let pages =
        inspect_logfile_pages(page_source.clone(), restart_limits(), page_limits(), &r).unwrap();
    assert!(pages.scan_complete());
    assert!(pages.stopping_error().is_none());
    assert!(pages.source_error().is_none());
    assert!(pages.restart().copies_disagree());
    assert_eq!(
        pages.pages().len(),
        report.copies()[0].area().unwrap().file_bytes as usize / 4096 - 2
    );
    assert_eq!(
        page_source.reads.load(Ordering::SeqCst),
        pages.pages().len() as u64 + 2
    );
    let mut physical = String::new();
    for (index, page) in pages.pages().iter().enumerate() {
        assert!(page.read_complete());
        assert_eq!(page.offset(), (index as u64 + 2) * 4096);
        assert_eq!(
            page.role(),
            if index < 32 {
                NtfsLogPageRole::FastCopy { index: index as u8 }
            } else {
                NtfsLogPageRole::Ordinary
            }
        );
        writeln!(
            physical,
            "offset={} role={:?} kind={:?} header={:?} error={:?} raw_sha256={:x}",
            page.offset(),
            page.role(),
            page.kind(),
            page.header(),
            page.error(),
            Sha256::digest(page.raw())
        )
        .unwrap();
    }
    let rows: Vec<_> = oracle_text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(rows.len(), pages.pages().len());
    for (row, page) in rows.iter().zip(pages.pages()) {
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(fields[0].parse::<u64>().unwrap(), page.offset());
        assert_eq!(
            fields[1],
            if matches!(page.role(), NtfsLogPageRole::FastCopy { .. }) {
                "fast"
            } else {
                "ordinary"
            }
        );
        assert_eq!(fields[3], format!("{:x}", Sha256::digest(page.raw())));
        match fields[2] {
            "rcrd" => {
                assert_eq!(fields.len(), 14);
                let header = page.header().unwrap();
                let number = |i: usize| fields[i].parse::<u64>().unwrap();
                assert_eq!(header.raw_lsn_or_file_offset, number(7));
                assert_eq!(u64::from(header.flags), number(8));
                assert_eq!(u64::from(header.page_count), number(9));
                assert_eq!(u64::from(header.page_position), number(10));
                assert_eq!(u64::from(header.next_record_offset), number(11));
                assert_eq!(header.last_end_lsn, number(12));
                let usa = usize::from(u16::from_le_bytes(page.raw()[4..6].try_into().unwrap()));
                let count = usize::from(u16::from_le_bytes(page.raw()[6..8].try_into().unwrap()));
                assert_eq!(usa as u64, number(5));
                assert_eq!(count as u64, number(6));
                let mut fixed = page.raw().to_vec();
                for sector in 1..count {
                    let trailer = sector * 512 - 2;
                    fixed[trailer..trailer + 2]
                        .copy_from_slice(&page.raw()[usa + sector * 2..usa + sector * 2 + 2]);
                }
                assert_eq!(fields[4], format!("{:x}", Sha256::digest(&fixed)));
                if fields[13] == "-" {
                    assert_eq!(header.fast_copy_target, None);
                    assert!(!header.fast_copy_target_checked);
                } else {
                    assert_eq!(
                        header.fast_copy_target,
                        Some(fields[13].parse::<u32>().unwrap())
                    );
                    assert!(header.fast_copy_target_checked);
                }
                if header.flags & !1 == 0 {
                    assert!(page.semantics_supported());
                } else {
                    assert_eq!(page.error().unwrap().kind, ErrorKind::Unsupported);
                    assert!(!page.semantics_supported());
                }
            }
            "ones" | "zero" => {
                assert_eq!(fields.len(), 4);
                assert!(page.header().is_none());
                assert_eq!(page.error().unwrap().kind, ErrorKind::Unsupported);
                let expected = if fields[2] == "ones" { 255 } else { 0 };
                assert!(page.raw().iter().all(|byte| *byte == expected));
            }
            other => panic!("unsupported independent page class: {other}"),
        }
    }
    fs::write(out.join("physical-pages.txt"), physical).unwrap();
    assert!(!pages.active_window_complete());
    assert!(!pages.transaction_analysis_complete());
    let query = report.copies()[0].area().unwrap().current_lsn;
    let record = inspect_logfile_record(
        direct_source.clone(),
        restart_limits(),
        record_limits(),
        query,
        &r,
    )
    .unwrap();
    assert_eq!(
        record.stopping_error().unwrap().kind,
        ErrorKind::InvalidData
    );
    assert!(record.pages().is_empty());
    assert!(record.payload().is_none());
    assert!(!record.complete());
    assert!(!record.active_window_complete());
    assert!(!record.transaction_analysis_complete());
    assert_eq!(
        direct_source.reads.load(Ordering::SeqCst),
        4,
        "restart and rejected record query read only restart candidates"
    );
    let native_pages = inspect_ntfs_logfile_pages(
        volume_source.clone(),
        read_limits(),
        stream_limits(),
        restart_limits(),
        page_limits(),
        &r,
    )
    .unwrap();
    assert!(native_pages.report.scan_complete());
    assert!(native_pages.report.stopping_error().is_none());
    assert!(native_pages.report.source_error().is_none());
    assert!(!native_pages.report.active_window_complete());
    assert!(!native_pages.report.transaction_analysis_complete());
    assert_eq!(native_pages.report.pages().len(), pages.pages().len());
    for (direct, native) in pages.pages().iter().zip(native_pages.report.pages()) {
        assert_eq!(direct.offset(), native.offset());
        assert_eq!(direct.role(), native.role());
        assert_eq!(direct.raw(), native.raw());
        assert_eq!(direct.header(), native.header());
        assert_eq!(
            direct.error().map(|error| error.kind),
            native.error().map(|error| error.kind)
        );
    }
    let native_record = inspect_ntfs_logfile_record(
        volume_source.clone(),
        read_limits(),
        stream_limits(),
        restart_limits(),
        record_limits(),
        query,
        &r,
    )
    .unwrap();
    assert_eq!(
        native_record.report.stopping_error().unwrap().kind,
        ErrorKind::InvalidData
    );
    assert!(native_record.report.pages().is_empty());
    assert!(!native_record.report.complete());
    let mut record_observations = String::new();
    for copy in 0..2u8 {
        let query = NtfsLogRecordQuery {
            lsn: report.copies()[usize::from(copy)]
                .area()
                .unwrap()
                .current_lsn,
            restart_copy: copy,
        };
        let direct = inspect_logfile_record_in_restart(
            page_source.clone(),
            restart_limits(),
            record_limits(),
            query,
            &r,
        )
        .unwrap();
        assert!(
            direct.complete(),
            "copy {copy}: {:?}",
            direct.stopping_error()
        );
        assert!(direct.stopping_error().is_none());
        assert_eq!(direct.requested_restart_copy(), Some(copy));
        assert!(direct.restart().copies_disagree());
        assert_eq!(
            direct.restart_context().unwrap(),
            report.copies()[usize::from(copy)].area().unwrap()
        );
        assert_eq!(direct.header().unwrap().this_lsn, query.lsn);
        assert_eq!(direct.header().unwrap().record_type, 2);
        assert_eq!(direct.payload().unwrap().len(), 112);
        assert!(!direct.page_flag_semantics_supported());
        assert!(!direct.active_window_complete());
        assert!(!direct.transaction_analysis_complete());
        let fields: Vec<_> = record_rows[usize::from(copy)].split('\t').collect();
        assert_eq!(fields.len(), 12);
        let number = |i: usize| fields[i].parse::<u64>().unwrap();
        let header = direct.header().unwrap();
        assert_eq!(number(0), u64::from(copy));
        assert_eq!(number(1), header.this_lsn);
        assert_eq!(number(2), header.previous_lsn);
        assert_eq!(number(3), header.undo_next_lsn);
        assert_eq!(number(4), u64::from(header.payload_bytes));
        assert_eq!(number(5), u64::from(header.client_sequence));
        assert_eq!(number(6), u64::from(header.client_index));
        assert_eq!(number(7), u64::from(header.record_type));
        assert_eq!(number(8), u64::from(header.transaction_id));
        assert_eq!(number(9), u64::from(header.flags));
        assert_eq!(
            fields[10],
            format!("{:x}", Sha256::digest(direct.payload().unwrap()))
        );
        assert_eq!(
            fields[11]
                .split(',')
                .map(|offset| offset.parse::<u64>().unwrap())
                .collect::<Vec<_>>(),
            direct
                .pages()
                .iter()
                .map(|page| page.offset())
                .collect::<Vec<_>>()
        );

        let dump_limits = NtfsLogCheckpointDumpLimits {
            restart: restart_limits(),
            record: record_limits(),
            table: NtfsLogRestartTableLimits {
                entries: 65535,
                bytes: 1 << 20,
                work: 200000,
            },
            queries: 5,
            pages: 128,
            payload_bytes: 4 << 20,
            work: 8 << 20,
        };
        let loaded =
            inspect_logfile_checkpoint_dumps(page_source.clone(), dump_limits, query, &r).unwrap();
        assert!(
            loaded.complete(),
            "copy {copy} loader: {:?}",
            loaded.stopping_error()
        );
        assert_eq!(loaded.queries(), 4);
        assert_eq!(loaded.checkpoint().payload(), direct.payload());
        assert!(!loaded.active_window_complete());
        assert!(!loaded.transaction_analysis_complete());
        let native_loaded = inspect_ntfs_logfile_checkpoint_dumps(
            volume_source.clone(),
            read_limits(),
            stream_limits(),
            dump_limits,
            query,
            &r,
        )
        .unwrap();
        assert!(native_loaded.report.complete());
        assert_eq!(native_loaded.owner.native, selected.owner.native);
        assert_eq!(native_loaded.owner.generation, selected.owner.generation);
        assert_ne!(native_loaded.owner.source, selected.owner.source);
        assert_eq!(native_loaded.volume_flags, selected.volume_flags);
        for (index, (a, b)) in loaded
            .dumps()
            .iter()
            .zip(native_loaded.report.dumps())
            .enumerate()
        {
            assert_eq!(a.reference(), b.reference());
            if index == 3 {
                assert_eq!(a.reference().bytes, 0);
                assert!(a.record().is_none());
                assert!(b.record().is_none());
            } else {
                assert_eq!(a.reference_bytes_match(), Some(true));
                assert_eq!(b.reference_bytes_match(), Some(true));
                assert_eq!(a.table_validated(), index != 1);
                assert_eq!(a.table_validated(), b.table_validated());
                assert_eq!(a.record().unwrap().payload(), b.record().unwrap().payload());
                let expected: Vec<_> = table_rows[usize::from(copy) * 3 + index]
                    .split('\t')
                    .collect();
                assert_eq!(
                    expected[12],
                    format!(
                        "{:x}",
                        Sha256::digest(a.record().unwrap().payload().unwrap())
                    )
                );
            }
        }
        let checkpoint = inspect_ntfs_client_restart(&direct).unwrap();
        let cp: Vec<_> = checkpoint_rows[usize::from(copy)].split('\t').collect();
        assert_eq!(cp.len(), 21);
        let value = |i: usize| cp[i].parse::<u64>().unwrap();
        assert_eq!(value(0), u64::from(copy));
        assert_eq!(value(1), query.lsn);
        assert_eq!(cp[2], format!("{:x}", Sha256::digest(checkpoint.raw())));
        assert_eq!(
            checkpoint.version,
            (cp[3].parse::<u32>().unwrap(), cp[4].parse::<u32>().unwrap())
        );
        assert_eq!(checkpoint.checkpoint_start_lsn, value(5));
        for (table, lsn_at, size_at) in [
            (checkpoint.open_attribute_table, 6, 10),
            (checkpoint.attribute_names, 7, 11),
            (checkpoint.dirty_page_table, 8, 12),
            (checkpoint.transaction_table, 9, 13),
        ] {
            assert_eq!(table.lsn, value(lsn_at));
            assert_eq!(u64::from(table.bytes), value(size_at));
        }
        assert_eq!(
            checkpoint.usn_journal_restart_offset,
            Some(cp[14].parse::<i64>().unwrap())
        );
        assert_eq!(checkpoint.last_lsn, Some(value(15)));
        assert_eq!(
            checkpoint.bytes_per_cluster,
            Some(cp[16].parse::<u32>().unwrap())
        );
        assert_eq!(
            checkpoint
                .reserved_bytes()
                .unwrap()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            cp[17]
        );
        assert_eq!(checkpoint.usn_journal_reference, Some(value(18)));
        assert_eq!(checkpoint.usn_base, Some(cp[19].parse::<i64>().unwrap()));
        assert_eq!(checkpoint.oldest_lsn, Some(value(20)));
        assert!(checkpoint.trailing_bytes().is_empty());
        writeln!(
            record_observations,
            "restart_copy={copy} checkpoint={checkpoint:?}"
        )
        .unwrap();
        let native = inspect_ntfs_logfile_record_in_restart(
            volume_source.clone(),
            read_limits(),
            stream_limits(),
            restart_limits(),
            record_limits(),
            query,
            &r,
        )
        .unwrap();
        assert!(
            native.report.complete(),
            "copy {copy}: {:?}",
            native.report.stopping_error()
        );
        assert_eq!(native.owner.native, selected.owner.native);
        assert_eq!(native.owner.generation, selected.owner.generation);
        assert_eq!(native.volume_flags, selected.volume_flags);
        assert_eq!(native.report.requested_restart_copy(), Some(copy));
        assert_eq!(native.report.restart_context(), direct.restart_context());
        assert_eq!(native.report.header(), direct.header());
        assert_eq!(native.report.payload(), direct.payload());
        assert_eq!(native.report.pages().len(), direct.pages().len());
        for (index, (a, b)) in direct.pages().iter().zip(native.report.pages()).enumerate() {
            assert_eq!(a.offset(), b.offset());
            assert_eq!(a.raw(), b.raw());
            assert_eq!(a.header(), b.header());
            fs::write(
                out.join(format!("copy-{copy}-record-page-{index}.bin")),
                a.raw(),
            )
            .unwrap();
        }
        fs::write(
            out.join(format!("copy-{copy}-record-payload.bin")),
            direct.payload().unwrap(),
        )
        .unwrap();
        writeln!(record_observations,"restart_copy={copy} query_lsn={} context={:?} header={:?} payload_sha256={:x} page_offsets={:?}",query.lsn,direct.restart_context(),direct.header(),Sha256::digest(direct.payload().unwrap()),direct.pages().iter().map(|page|page.offset()).collect::<Vec<_>>()).unwrap();
    }
    let mut table_observations = String::new();
    for (row_index, row) in table_rows.iter().enumerate() {
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(fields.len(), 20);
        let number = |i: usize| fields[i].parse::<u64>().unwrap();
        let copy = (row_index / 3) as u8;
        let (name, operation, cp_lsn, cp_bytes) = match row_index % 3 {
            0 => ("open_attribute", 29u16, 6, 10),
            1 => ("attribute_names", 30u16, 7, 11),
            _ => ("dirty_pages", 31u16, 8, 12),
        };
        assert_eq!(number(0), u64::from(copy));
        assert_eq!(fields[1], name);
        let checkpoint: Vec<_> = checkpoint_rows[usize::from(copy)].split('\t').collect();
        assert_eq!(fields[2], checkpoint[cp_lsn]);
        let query = NtfsLogRecordQuery {
            lsn: number(2),
            restart_copy: copy,
        };
        let direct = inspect_logfile_record_in_restart(
            page_source.clone(),
            restart_limits(),
            record_limits(),
            query,
            &r,
        )
        .unwrap();
        assert!(
            direct.complete(),
            "{name} copy {copy}: {:?}",
            direct.stopping_error()
        );
        let h = direct.header().unwrap();
        for (index, observed) in [
            (2, h.this_lsn),
            (3, h.previous_lsn),
            (4, h.undo_next_lsn),
            (5, u64::from(h.payload_bytes)),
            (6, u64::from(h.client_sequence)),
            (7, u64::from(h.client_index)),
            (8, u64::from(h.record_type)),
            (9, u64::from(h.transaction_id)),
            (10, u64::from(h.flags)),
        ] {
            assert_eq!(number(index), observed);
        }
        assert_eq!(
            fields[11]
                .split(',')
                .map(|v| v.parse::<u64>().unwrap())
                .collect::<Vec<_>>(),
            direct
                .pages()
                .iter()
                .map(|p| p.offset())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            fields[12],
            format!("{:x}", Sha256::digest(direct.payload().unwrap()))
        );
        let client = inspect_ntfs_log_client_record(&direct).unwrap();
        assert_eq!(client.redo_operation, operation);
        assert_eq!(number(13), u64::from(client.redo_operation));
        assert_eq!(number(14), u64::from(client.undo_operation));
        assert_eq!(number(16), client.redo().len() as u64);
        assert_eq!(number(18), client.undo().len() as u64);
        assert_eq!(number(16), checkpoint[cp_bytes].parse::<u64>().unwrap());
        for (column, offset) in [(15, 4), (17, 8)] {
            assert_eq!(
                number(column),
                u64::from(u16::from_le_bytes(
                    client.raw()[offset..offset + 2].try_into().unwrap()
                ))
            );
        }
        assert_eq!(fields[19], format!("{:x}", Sha256::digest(client.redo())));
        if operation != 30 {
            let table = inspect_ntfs_log_restart_table(
                &client,
                NtfsLogRestartTableLimits {
                    entries: 65535,
                    bytes: 1 << 20,
                    work: 200000,
                },
                &r,
            )
            .unwrap();
            assert!(!table.entry_semantics_supported());
            writeln!(
                table_observations,
                "copy={copy} reference={name} table={table:?}"
            )
            .unwrap();
        }
        let native = inspect_ntfs_logfile_record_in_restart(
            volume_source.clone(),
            read_limits(),
            stream_limits(),
            restart_limits(),
            record_limits(),
            query,
            &r,
        )
        .unwrap();
        assert!(native.report.complete());
        assert_eq!(native.report.payload(), direct.payload());
        assert_eq!(native.report.header(), direct.header());
        assert!(!client.operation_semantics_supported());
        assert!(!direct.envelope_flag_semantics_supported());
        fs::write(
            out.join(format!("copy-{copy}-{name}-payload.bin")),
            client.raw(),
        )
        .unwrap();
    }
    fs::write(
        out.join("checkpoint-table-observations.txt"),
        table_observations,
    )
    .unwrap();
    fs::write(out.join("contextual-records.txt"), record_observations).unwrap();
    fs::write(out.join("observations.txt"), observations).unwrap();
    fs::write(out.join("report.txt"),format!("scope=Windows power-cut pre-recovery 2.0 restart framing and exact native record-2 stream selection; divergent copies preserved; physical 2.0 fast-copy and ordinary page inventory without copy selection; exact 2.0 record queries in each caller-selected restart context without authoritative selection; client checkpoint fields and source-owned reference loading through direct/native selection, explicit table-anchor envelopes/redo bytes with generic table links validated, names bytes opaque; no active-window, transaction, replay, mutation or recovery qualification\nstate={:?}\ncopies_disagree={}\nowner={:?}\nvolume_flags={}\nstream_sha256={stream_hash:x}\nvolume_sha256={volume_hash:x}\nfixture_receipt_sha256={receipt_hash:x}\ntest_binary_sha256={binary_hash:x}\n",report.state(),report.copies_disagree(),selected.owner,selected.volume_flags)).unwrap();
    drop(native_record);
    drop(native_pages);
    drop(record);
    drop(pages);
    drop(selected);
    drop(report);
    assert_eq!(r.memory.used(), 0);
    assert_eq!(Sha256::digest(fs::read(&stream_path).unwrap()), stream_hash);
    assert_eq!(Sha256::digest(fs::read(&volume_path).unwrap()), volume_hash);
    assert_eq!(
        Sha256::digest(fs::read(&receipt_path).unwrap()),
        receipt_hash
    );
    assert_eq!(Sha256::digest(fs::read(&binary_path).unwrap()), binary_hash);
    assert_eq!(Sha256::digest(fs::read(&oracle_path).unwrap()), oracle_hash);
    assert_eq!(
        Sha256::digest(fs::read(&record_oracle_path).unwrap()),
        record_oracle_hash
    );
    assert_eq!(
        Sha256::digest(fs::read(&checkpoint_oracle_path).unwrap()),
        checkpoint_oracle_hash
    );
    assert_eq!(
        Sha256::digest(fs::read(&table_oracle_path).unwrap()),
        table_oracle_hash
    );
    assert_eq!(check_sources(), source_start);
    fs::write(out.join("source-end.sha256"), check_sources()).unwrap();
}
