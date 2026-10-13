#![cfg(feature = "std")]
//! Explicit Windows-authored version-1.1 restart, page and exact-record observations.
//! Offline on-disk version is checked independently of mounted fsutil output.
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_ntfs_logfile::{
        NtfsLogFileLimits, NtfsLogFileState, NtfsLogPageKind, NtfsLogPageLimits, NtfsLogPageRole,
        NtfsLogRecordLimits, inspect_logfile, inspect_logfile_pages, inspect_logfile_record,
        inspect_ntfs_logfile, inspect_ntfs_logfile_pages, inspect_ntfs_logfile_record,
    },
    io,
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, sync::Arc};
use virtdisk::ReadAt;
struct Stream(Vec<u8>);
impl ReadAt for Stream {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}
#[test]
#[ignore = "explicit Windows-authored logfile gate requires exact stream/volume, provenance receipt, independent page/record oracles, source root, and fresh evidence directory"]
fn native_clean_restart_matches_windows_authored_volume() {
    let required = |name| PathBuf::from(std::env::var_os(name).expect(name));
    let stream_path = required("PARTMGR_NTFS_LOGFILE_STREAM");
    let volume_path = required("PARTMGR_NTFS_LOGFILE_VOLUME");
    let receipt_path = required("PARTMGR_NTFS_LOGFILE_FIXTURE_RECEIPT");
    let oracle_path = required("PARTMGR_NTFS_LOGFILE_PAGE_ORACLE");
    let record_oracle_path = required("PARTMGR_NTFS_LOGFILE_RECORD_ORACLE");
    let source_root = required("PARTMGR_GATE_SOURCE_ROOT");
    let out = required("PARTMGR_NTFS_LOGFILE_EVIDENCE");
    fs::create_dir(&out).expect("fresh evidence directory required");
    let sources: &[(&str, &[u8])] = &[
        ("Cargo.toml", include_bytes!("../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../Cargo.lock")),
        ("src/lib.rs", include_bytes!("../src/lib.rs")),
        ("src/fs_core.rs", include_bytes!("../src/fs_core.rs")),
        ("src/io.rs", include_bytes!("../src/io.rs")),
        ("src/platform.rs", include_bytes!("../src/platform.rs")),
        ("src/fs_file.rs", include_bytes!("../src/fs_file.rs")),
        ("src/storage.rs", include_bytes!("../src/storage.rs")),
        (
            "src/fs_ntfs_logfile.rs",
            include_bytes!("../src/fs_ntfs_logfile.rs"),
        ),
        (
            "src/fs_ntfs_logfile/pages.rs",
            include_bytes!("../src/fs_ntfs_logfile/pages.rs"),
        ),
        (
            "src/fs_ntfs_logfile/record.rs",
            include_bytes!("../src/fs_ntfs_logfile/record.rs"),
        ),
        (
            "src/fs_ntfs_logfile/checkpoint.rs",
            include_bytes!("../src/fs_ntfs_logfile/checkpoint.rs"),
        ),
        (
            "src/fs_ntfs_logfile/table_entries.rs",
            include_bytes!("../src/fs_ntfs_logfile/table_entries.rs"),
        ),
        (
            "src/fs_ntfs_logfile/checkpoint_dumps.rs",
            include_bytes!("../src/fs_ntfs_logfile/checkpoint_dumps.rs"),
        ),
        (
            "src/fs_ntfs_logfile/client_record.rs",
            include_bytes!("../src/fs_ntfs_logfile/client_record.rs"),
        ),
        (
            "src/fs_ntfs_logfile/restart_table.rs",
            include_bytes!("../src/fs_ntfs_logfile/restart_table.rs"),
        ),
        (
            "integration/maintenance/logfile-page-oracle.py",
            include_bytes!("../integration/maintenance/logfile-page-oracle.py"),
        ),
        (
            "integration/maintenance/logfile-record-oracle.py",
            include_bytes!("../integration/maintenance/logfile-record-oracle.py"),
        ),
        ("src/fs_ntfs.rs", include_bytes!("../src/fs_ntfs.rs")),
        (
            "src/fs_ntfs_stream.rs",
            include_bytes!("../src/fs_ntfs_stream.rs"),
        ),
        (
            "src/fs_ntfs_bootstrap.rs",
            include_bytes!("../src/fs_ntfs_bootstrap.rs"),
        ),
        (
            "src/fs_ntfs_compressed.rs",
            include_bytes!("../src/fs_ntfs_compressed.rs"),
        ),
        (
            "tests/fs_ntfs_logfile_native.rs",
            include_bytes!("../tests/fs_ntfs_logfile_native.rs"),
        ),
    ];
    let check_sources = || {
        use std::fmt::Write;
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
    fs::write(out.join("gate-binary"), &binary).unwrap();
    let stream = fs::read(&stream_path).expect("native stream required");
    let stream_hash = Sha256::digest(&stream);
    let oracle = fs::read_to_string(&oracle_path).expect("independent page oracle required");
    let oracle_hash = Sha256::digest(oracle.as_bytes());
    assert_eq!(
        oracle.lines().next().unwrap(),
        format!("# source_sha256={stream_hash:x}")
    );
    fs::write(out.join("physical-page-oracle.tsv"), &oracle).unwrap();
    let record_oracle = fs::read_to_string(&record_oracle_path).expect("record oracle required");
    let record_oracle_hash = Sha256::digest(record_oracle.as_bytes());
    assert_eq!(
        record_oracle.lines().next().unwrap(),
        format!("# source_sha256={stream_hash:x}")
    );
    fs::write(out.join("record-oracle.tsv"), &record_oracle).unwrap();
    let receipt = fs::read(&receipt_path).expect("native fixture provenance receipt required");
    assert!(
        !receipt.is_empty(),
        "native fixture provenance receipt empty"
    );
    let receipt_hash = Sha256::digest(&receipt);
    fs::write(out.join("fixture-provenance-receipt"), &receipt).unwrap();
    fs::write(
        out.join("command.txt"),
        format!(
            "argv={:?}\nstream={:?}\nfixture_receipt={:?}\nsource_root={:?}\nevidence={:?}\n",
            std::env::args_os().collect::<Vec<_>>(),
            stream_path,
            receipt_path,
            source_root,
            out
        ),
    )
    .unwrap();
    let resources = Resources {
        memory: Budget::new(128 << 20),
        cancellation: Cancellation::default(),
    };
    let stream_source = Arc::new(Stream(stream));
    let report = inspect_logfile(
        stream_source.clone(),
        NtfsLogFileLimits {
            restart_page_bytes: 4096,
            clients: 1,
            work: 1000,
        },
        &resources,
    )
    .unwrap();
    assert_eq!(report.state(), NtfsLogFileState::CleanFlagObserved);
    assert!(!report.transaction_analysis_complete());
    assert!(report.source_error().is_none());
    let pages = inspect_logfile_pages(
        stream_source.clone(),
        NtfsLogFileLimits {
            restart_page_bytes: 4096,
            clients: 1,
            work: 1000,
        },
        NtfsLogPageLimits {
            pages: 4096,
            retained_bytes: 16 << 20,
            work: 100_000,
        },
        &resources,
    )
    .unwrap();
    assert!(pages.scan_complete());
    assert!(pages.stopping_error().is_none());
    assert!(!pages.transaction_analysis_complete());
    let rows: Vec<_> = oracle
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(pages.pages().len(), rows.len());
    let mut physical = String::new();
    for (page, row) in pages.pages().iter().zip(rows) {
        use std::fmt::Write;
        let cells: Vec<_> = row.split('\t').collect();
        assert_eq!(page.offset(), cells[0].parse::<u64>().unwrap());
        assert_eq!(
            page.role(),
            match page.offset() {
                8192 => NtfsLogPageRole::TailCopy { index: 0 },
                12288 => NtfsLogPageRole::TailCopy { index: 1 },
                _ => NtfsLogPageRole::Ordinary,
            }
        );
        assert!(page.read_complete());
        assert_eq!(format!("{:x}", Sha256::digest(page.raw())), cells[2]);
        match cells[1] {
            "ones" => assert_eq!(page.kind(), NtfsLogPageKind::UninitializedOnes),
            "zero" => assert_eq!(page.kind(), NtfsLogPageKind::UninitializedZero),
            "rcrd" => {
                assert_eq!(page.kind(), NtfsLogPageKind::Record);
                assert!(page.framing_valid());
                let header = page.header().unwrap();
                assert_eq!(
                    header.raw_lsn_or_file_offset,
                    cells[3].parse::<u64>().unwrap()
                );
                assert_eq!(header.flags, cells[4].parse::<u32>().unwrap());
                assert_eq!(header.page_count, cells[5].parse::<u16>().unwrap());
                assert_eq!(header.page_position, cells[6].parse::<u16>().unwrap());
                assert_eq!(header.next_record_offset, cells[7].parse::<u16>().unwrap());
                assert_eq!(header.last_end_lsn, cells[8].parse::<u64>().unwrap());
                assert_eq!(page.semantics_supported(), header.flags & !1 == 0);
            }
            other => panic!("unknown independent oracle kind: {other}"),
        }
        writeln!(
            physical,
            "offset={} role={:?} kind={:?} header={:?} error={:?}",
            page.offset(),
            page.role(),
            page.kind(),
            page.header(),
            page.error()
        )
        .unwrap();
    }
    fs::write(out.join("physical-pages.txt"), physical).unwrap();
    let mut observations = String::new();
    for (index, copy) in report.copies().iter().enumerate() {
        use std::fmt::Write;
        assert!(copy.read_complete());
        let header = copy.header().expect("native restart header required");
        assert_eq!(header.version, (1, 1));
        assert_eq!(header.system_page_bytes, 4096);
        assert_eq!(header.log_page_bytes, 4096);
        let area = copy.area().expect("supported native restart area");
        assert_eq!(area.flags & 2, 2);
        fs::write(out.join(format!("restart-{index}.bin")), copy.raw()).unwrap();
        writeln!(
            observations,
            "copy={index} offset={} header={header:?} area={area:?}\n",
            copy.offset()
        )
        .unwrap();
    }
    let volume_bytes = fs::read(&volume_path).expect("native bounded volume required");
    let volume_hash = Sha256::digest(&volume_bytes);
    let volume_source = Arc::new(Stream(volume_bytes));
    let selected = inspect_ntfs_logfile(
        volume_source.clone(),
        partmgr::fs_ntfs::NtfsReadLimits {
            attributes: 128,
            runs: 256,
            names: 64,
        },
        partmgr::fs_ntfs::NtfsStreamLimits {
            extension_records: 128,
            list_entries: 2048,
            list_bytes: 1 << 20,
            attributes: 256,
            runs: 1024,
            work: 2 << 20,
        },
        NtfsLogFileLimits {
            restart_page_bytes: 4096,
            clients: 1,
            work: 1000,
        },
        &resources,
    )
    .unwrap();
    assert_eq!(selected.owner.native, 2u64.to_le_bytes());
    assert_ne!(selected.owner.generation, 0);
    assert_eq!(selected.volume_flags & 1, 0, "native volume dirty flag");
    assert_eq!(selected.report.state(), NtfsLogFileState::CleanFlagObserved);
    assert_eq!(selected.report.source_bytes(), report.source_bytes());
    assert!(!selected.report.transaction_analysis_complete());
    assert!(selected.report.source_error().is_none());
    for (direct, native) in report.copies().iter().zip(selected.report.copies()) {
        assert_eq!(direct.raw(), native.raw(), "native system-stream selection");
        assert_eq!(direct.area().unwrap(), native.area().unwrap());
    }
    let selected_pages = inspect_ntfs_logfile_pages(
        volume_source.clone(),
        partmgr::fs_ntfs::NtfsReadLimits {
            attributes: 128,
            runs: 256,
            names: 64,
        },
        partmgr::fs_ntfs::NtfsStreamLimits {
            extension_records: 128,
            list_entries: 2048,
            list_bytes: 1 << 20,
            attributes: 256,
            runs: 1024,
            work: 2 << 20,
        },
        NtfsLogFileLimits {
            restart_page_bytes: 4096,
            clients: 1,
            work: 1000,
        },
        NtfsLogPageLimits {
            pages: 4096,
            retained_bytes: 16 << 20,
            work: 100_000,
        },
        &resources,
    )
    .unwrap();
    // Each volume open has a distinct source scope; native identity and sequence
    // must match across these independent opens, not the scoped handle itself.
    assert_eq!(selected_pages.owner.native, selected.owner.native);
    assert_eq!(selected_pages.owner.generation, selected.owner.generation);
    assert_ne!(selected_pages.owner.source, selected.owner.source);
    assert_eq!(selected_pages.volume_flags, selected.volume_flags);
    assert_eq!(
        selected_pages.report.restart().source_bytes(),
        pages.restart().source_bytes()
    );
    assert!(selected_pages.report.scan_complete());
    assert!(selected_pages.report.stopping_error().is_none());
    assert!(!selected_pages.report.active_window_complete());
    assert_eq!(selected_pages.report.pages().len(), pages.pages().len());
    for (native, direct) in selected_pages.report.pages().iter().zip(pages.pages()) {
        assert_eq!(native.offset(), direct.offset());
        assert_eq!(native.role(), direct.role());
        assert_eq!(native.kind(), direct.kind());
        assert_eq!(native.raw(), direct.raw());
        assert_eq!(native.header(), direct.header());
        assert_eq!(
            native.error().map(|e| e.kind),
            direct.error().map(|e| e.kind)
        );
    }
    let read_limits = || partmgr::fs_ntfs::NtfsReadLimits {
        attributes: 128,
        runs: 256,
        names: 64,
    };
    let stream_limits = || partmgr::fs_ntfs::NtfsStreamLimits {
        extension_records: 128,
        list_entries: 2048,
        list_bytes: 1 << 20,
        attributes: 256,
        runs: 1024,
        work: 2 << 20,
    };
    let restart_limits = || NtfsLogFileLimits {
        restart_page_bytes: 4096,
        clients: 1,
        work: 1000,
    };
    let record_limits = || NtfsLogRecordLimits {
        pages: 4096,
        payload_bytes: 16 << 20,
        work: 100_000,
    };
    let mut record_count = 0;
    let mut record_observations = String::new();
    for row in record_oracle.lines().filter(|line| !line.starts_with('#')) {
        use std::fmt::Write;
        let cells: Vec<_> = row.split('\t').collect();
        assert_eq!(cells.len(), 11);
        let lsn = cells[0].parse::<u64>().unwrap();
        let direct = inspect_logfile_record(
            stream_source.clone(),
            restart_limits(),
            record_limits(),
            lsn,
            &resources,
        )
        .unwrap();
        assert!(
            direct.complete(),
            "query {lsn}: {:?}",
            direct.stopping_error()
        );
        assert!(!direct.page_flag_semantics_supported());
        assert!(!direct.active_window_complete());
        assert!(!direct.transaction_analysis_complete());
        let header = direct.header().unwrap();
        assert_eq!(header.this_lsn, lsn);
        assert_eq!(header.previous_lsn, cells[1].parse::<u64>().unwrap());
        assert_eq!(header.undo_next_lsn, cells[2].parse::<u64>().unwrap());
        assert_eq!(header.payload_bytes, cells[3].parse::<u32>().unwrap());
        assert_eq!(header.client_sequence, cells[4].parse::<u16>().unwrap());
        assert_eq!(header.client_index, cells[5].parse::<u16>().unwrap());
        assert_eq!(header.record_type, cells[6].parse::<u32>().unwrap());
        assert_eq!(header.transaction_id, cells[7].parse::<u32>().unwrap());
        assert_eq!(header.flags, cells[8].parse::<u16>().unwrap());
        assert_eq!(
            format!("{:x}", Sha256::digest(direct.payload().unwrap())),
            cells[9]
        );
        let expected_pages: Vec<u64> = cells[10].split(',').map(|v| v.parse().unwrap()).collect();
        assert_eq!(
            direct
                .pages()
                .iter()
                .map(|p| p.offset())
                .collect::<Vec<_>>(),
            expected_pages
        );
        let native = inspect_ntfs_logfile_record(
            volume_source.clone(),
            read_limits(),
            stream_limits(),
            restart_limits(),
            record_limits(),
            lsn,
            &resources,
        )
        .unwrap();
        assert_eq!(native.owner.native, selected.owner.native);
        assert_eq!(native.owner.generation, selected.owner.generation);
        assert_eq!(native.volume_flags, selected.volume_flags);
        assert!(
            native.report.complete(),
            "native query {lsn}: {:?}",
            native.report.stopping_error()
        );
        assert!(!native.report.page_flag_semantics_supported());
        assert_eq!(native.report.header(), direct.header());
        assert_eq!(native.report.payload(), direct.payload());
        fs::write(
            out.join(format!("record-{lsn}.bin")),
            direct.payload().unwrap(),
        )
        .unwrap();
        assert_eq!(native.report.pages().len(), direct.pages().len());
        for (a, b) in native.report.pages().iter().zip(direct.pages()) {
            assert_eq!(a.offset(), b.offset());
            assert_eq!(a.raw(), b.raw());
        }
        writeln!(
            record_observations,
            "lsn={lsn} header={header:?} payload_sha256={} pages={expected_pages:?}",
            cells[9]
        )
        .unwrap();
        record_count += 1;
    }
    assert!(
        record_count > 0,
        "independent oracle must identify native records"
    );
    fs::write(out.join("records.txt"), record_observations).unwrap();
    drop(selected_pages);
    drop(pages);
    fs::write(out.join("volume-selection.txt"), format!("volume_path={volume_path:?}\nvolume_sha256={volume_hash:x}\nowner={:?}\nvolume_flags={}\nstate={:?}\n", selected.owner, selected.volume_flags, selected.report.state())).unwrap();
    drop(selected);
    fs::write(out.join("observations.txt"), observations).unwrap();
    fs::write(out.join("report.txt"), format!("scope=Windows-authored offline 1.1 restart framing, physical page headers, exact record envelope/payload observations and native system-stream selection; no active-window/replay/mutation qualification\nstate={:?}\ntransaction_analysis_complete={}\nwork={}\nrecord_count={record_count}\nstream_sha256={stream_hash:x}\nfixture_receipt_sha256={receipt_hash:x}\npage_oracle_sha256={oracle_hash:x}\nrecord_oracle_sha256={record_oracle_hash:x}\ntest_binary_sha256={binary_hash:x}\n", report.state(), report.transaction_analysis_complete(), report.work())).unwrap();
    drop(report);
    assert_eq!(resources.memory.used(), 0);
    assert_eq!(Sha256::digest(fs::read(&volume_path).unwrap()), volume_hash);
    assert_eq!(Sha256::digest(fs::read(&stream_path).unwrap()), stream_hash);
    assert_eq!(Sha256::digest(fs::read(&oracle_path).unwrap()), oracle_hash);
    assert_eq!(
        Sha256::digest(fs::read(&record_oracle_path).unwrap()),
        record_oracle_hash
    );
    assert_eq!(
        Sha256::digest(fs::read(&receipt_path).unwrap()),
        receipt_hash
    );
    assert_eq!(Sha256::digest(fs::read(&binary_path).unwrap()), binary_hash);
    assert_eq!(check_sources(), source_start);
    fs::write(out.join("source-end.sha256"), check_sources()).unwrap();
}
