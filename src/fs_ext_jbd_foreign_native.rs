//! Explicit independently authored native-format preflight qualification only.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    fmt::Write,
    fs,
    path::{Path, PathBuf},
};

#[path = "fs_ext_jbd_foreign_native_cuts.rs"]
mod cuts;

struct NoWrites {
    bytes: Vec<u8>,
    writes: Cell<usize>,
}
impl Storage for NoWrites {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(
            self.bytes
                .get(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        self.writes.set(self.writes.get() + 1);
        panic!("foreign preflight must never write")
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("foreign preflight must never flush")
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn required(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).expect(name));
    assert!(path.is_absolute(), "absolute {name} required");
    path
}
fn check(path: &Path, expected: &str) -> Vec<u8> {
    let bytes = fs::read(path).unwrap();
    assert_eq!(hash(&bytes), expected, "{}", path.display());
    bytes
}

#[test]
#[ignore = "requires pinned independent ext3 corpus, receipt, native tools, source root and fresh evidence destination"]
fn native_foreign_preflight_matches_independent_e2fsprogs_overlay() {
    qualify(false, false);
}

#[test]
#[ignore = "requires pinned independent ext3 corpus, receipt, native tools, source root and fresh evidence destination"]
fn native_foreign_recovery_matches_independent_e2fsprogs_overlay() {
    qualify(true, false);
}

#[test]
#[ignore = "requires pinned independent ext3 corpus, native tools and fresh cut evidence"]
fn native_foreign_recovery_cuts_match_independent_e2fsprogs_overlay() {
    qualify(true, true);
}

fn qualify(recovery: bool, cut_artifacts: bool) {
    let corpus = required("PARTMGR_EXT_FOREIGN_CORPUS");
    let receipt_path = required("PARTMGR_EXT_FOREIGN_RECEIPT");
    let root = required("PARTMGR_GATE_SOURCE_ROOT");
    let out = required("PARTMGR_EXT_FOREIGN_EVIDENCE");
    fs::create_dir(&out).expect("fresh evidence directory required");
    let receipt = check(
        &receipt_path,
        "d41db945ad24e9fe013fca1a6b0b69e826e03d358eaf8d9f28b491fa730a83de",
    );
    let receipt_text = std::str::from_utf8(&receipt).unwrap();
    fs::write(out.join("fixture-receipt.json"), &receipt).unwrap();
    macro_rules! source {
        ($name:literal) => {
            ($name, &include_bytes!(concat!("../", $name))[..])
        };
    }
    let sources: &[(&str, &[u8])] = &[
        source!("Cargo.toml"),
        source!("Cargo.lock"),
        source!("src/bitlocker.rs"),
        source!("src/bitlocker_crypto.rs"),
        source!("src/bitlocker_disk.rs"),
        source!("src/bitlocker_swtpm.rs"),
        source!("src/bitlocker_tpm.rs"),
        source!("src/bitlocker_tpm_host.rs"),
        source!("src/bitlocker_write.rs"),
        source!("src/codec.rs"),
        source!("src/conversion.rs"),
        source!("src/editor.rs"),
        source!("src/error.rs"),
        source!("src/extended.rs"),
        source!("src/fs_apfs.rs"),
        source!("src/fs_apfs_audit.rs"),
        source!("src/fs_apfs_builder.rs"),
        source!("src/fs_apfs_builder_disk.rs"),
        source!("src/fs_apfs_builder_layout.rs"),
        source!("src/fs_apfs_disk.rs"),
        source!("src/fs_apfs_edit.rs"),
        source!("src/fs_apfs_edit_cow.rs"),
        source!("src/fs_apfs_edit_disk.rs"),
        source!("src/fs_apfs_edit_namespace.rs"),
        source!("src/fs_apfs_edit_reclaim.rs"),
        source!("src/fs_apfs_edit_retention.rs"),
        source!("src/fs_apfs_edit_tree.rs"),
        source!("src/fs_apfs_index.rs"),
        source!("src/fs_apfs_retention.rs"),
        source!("src/fs_apfs_tree.rs"),
        source!("src/fs_build_io.rs"),
        source!("src/fs_copy.rs"),
        source!("src/fs_core.rs"),
        source!("src/fs_discovery.rs"),
        source!("src/fs_exfat.rs"),
        source!("src/fs_exfat_audit.rs"),
        source!("src/fs_exfat_builder.rs"),
        source!("src/fs_exfat_copy.rs"),
        source!("src/fs_exfat_edit.rs"),
        source!("src/fs_exfat_edit_namespace.rs"),
        source!("src/fs_exfat_tree.rs"),
        source!("src/fs_exfat_volume.rs"),
        source!("src/fs_ext.rs"),
        source!("src/fs_ext_audit.rs"),
        source!("src/fs_ext_builder.rs"),
        source!("src/fs_ext_checksum.rs"),
        source!("src/fs_ext_copy.rs"),
        source!("src/fs_ext_directory.rs"),
        source!("src/fs_ext_edit.rs"),
        source!("src/fs_ext_edit_allocation.rs"),
        source!("src/fs_ext_edit_namespace.rs"),
        source!("src/fs_ext_edit_transaction.rs"),
        source!("src/fs_ext_extent.rs"),
        source!("src/fs_ext_hash.rs"),
        source!("src/fs_ext_integrity.rs"),
        source!("src/fs_ext_jbd.rs"),
        source!("src/fs_ext_jbd_bootstrap.rs"),
        source!("src/fs_ext_jbd_foreign.rs"),
        source!("src/fs_ext_jbd_foreign_native.rs"),
        source!("src/fs_ext_jbd_foreign_native_cuts.rs"),
        source!("src/fs_ext_jbd_foreign_recover_tests.rs"),
        source!("src/fs_ext_jbd_legacy.rs"),
        source!("src/fs_ext_jbd_modern_extent.rs"),
        source!("src/fs_ext_jbd_modern_htree.rs"),
        source!("src/fs_ext_jbd_modern_indirect.rs"),
        source!("src/fs_ext_jbd_modern_indirect_tests.rs"),
        source!("src/fs_ext_jbd_modern_inode.rs"),
        source!("src/fs_ext_jbd_modern_namespace.rs"),
        source!("src/fs_ext_jbd_modern_namespace_tests.rs"),
        source!("src/fs_ext_jbd_modern_plan.rs"),
        source!("src/fs_ext_jbd_modern_tests.rs"),
        source!("src/fs_ext_jbd_native.rs"),
        source!("src/fs_ext_jbd_native_indirect.rs"),
        source!("src/fs_ext_jbd_native_inode.rs"),
        source!("src/fs_ext_jbd_native_legacy.rs"),
        source!("src/fs_ext_jbd_native_namespace.rs"),
        source!("src/fs_ext_jbd_overlay.rs"),
        source!("src/fs_ext_jbd_recovery.rs"),
        source!("src/fs_ext_jbd_session.rs"),
        source!("src/fs_ext_jbd_transaction.rs"),
        source!("src/fs_ext_journal.rs"),
        source!("src/fs_ext_metadata.rs"),
        source!("src/fs_ext_modern.rs"),
        source!("src/fs_ext_resize.rs"),
        source!("src/fs_ext_tree.rs"),
        source!("src/fs_ext_xattr.rs"),
        source!("src/fs_fat.rs"),
        source!("src/fs_fat_audit.rs"),
        source!("src/fs_fat_builder.rs"),
        source!("src/fs_fat_edit.rs"),
        source!("src/fs_fat_edit_namespace.rs"),
        source!("src/fs_fat_edit_resize.rs"),
        source!("src/fs_fat_tree.rs"),
        source!("src/fs_file.rs"),
        source!("src/fs_flash.rs"),
        source!("src/fs_hfs.rs"),
        source!("src/fs_hfs_audit.rs"),
        source!("src/fs_hfs_tree.rs"),
        source!("src/fs_hfsplus.rs"),
        source!("src/fs_hfsplus_allocation_builder.rs"),
        source!("src/fs_hfsplus_audit.rs"),
        source!("src/fs_hfsplus_builder.rs"),
        source!("src/fs_hfsplus_builder_inventory.rs"),
        source!("src/fs_hfsplus_builder_layout.rs"),
        source!("src/fs_hfsplus_edit.rs"),
        source!("src/fs_hfsplus_fork_builder.rs"),
        source!("src/fs_hfsplus_metadata_builder.rs"),
        source!("src/fs_hfsplus_node.rs"),
        source!("src/fs_hfsplus_owned_create.rs"),
        source!("src/fs_hfsplus_owned_cuts.rs"),
        source!("src/fs_hfsplus_owned_namespace.rs"),
        source!("src/fs_hfsplus_owned_namespace_cuts.rs"),
        source!("src/fs_hfsplus_owned_namespace_native.rs"),
        source!("src/fs_hfsplus_owned_namespace_native_cuts.rs"),
        source!("src/fs_hfsplus_owned_prepare.rs"),
        source!("src/fs_hfsplus_owned_recovery.rs"),
        source!("src/fs_hfsplus_owned_resize.rs"),
        source!("src/fs_hfsplus_owned_resize_commit.rs"),
        source!("src/fs_hfsplus_owned_resize_cuts.rs"),
        source!("src/fs_hfsplus_owned_resize_forks_native.rs"),
        source!("src/fs_hfsplus_owned_resize_metadata.rs"),
        source!("src/fs_hfsplus_owned_resize_native.rs"),
        source!("src/fs_hfsplus_owned_resize_native_cuts.rs"),
        source!("src/fs_hfsplus_owned_resize_recovery.rs"),
        source!("src/fs_hfsplus_owned_transaction.rs"),
        source!("src/fs_hfsplus_tree.rs"),
        source!("src/fs_image.rs"),
        source!("src/fs_jffs2.rs"),
        source!("src/fs_jffs2_audit.rs"),
        source!("src/fs_jffs2_builder.rs"),
        source!("src/fs_jffs2_builder_compression.rs"),
        source!("src/fs_jffs2_compression.rs"),
        source!("src/fs_jffs2_edit.rs"),
        source!("src/fs_jffs2_edit_compression.rs"),
        source!("src/fs_jffs2_edit_compression_tests.rs"),
        source!("src/fs_jffs2_edit_file.rs"),
        source!("src/fs_jffs2_edit_gc.rs"),
        source!("src/fs_jffs2_edit_journal.rs"),
        source!("src/fs_jffs2_edit_namespace.rs"),
        source!("src/fs_jffs2_tree.rs"),
        source!("src/fs_jfs.rs"),
        source!("src/fs_jfs_audit.rs"),
        source!("src/fs_jfs_edit.rs"),
        source!("src/fs_jfs_edit_allocation.rs"),
        source!("src/fs_jfs_edit_journal.rs"),
        source!("src/fs_jfs_edit_namespace.rs"),
        source!("src/fs_jfs_edit_rename.rs"),
        source!("src/fs_jfs_edit_rollover.rs"),
        source!("src/fs_jfs_tree.rs"),
        source!("src/fs_maintenance.rs"),
        source!("src/fs_maintenance_audit.rs"),
        source!("src/fs_ntfs.rs"),
        source!("src/fs_ntfs_audit.rs"),
        source!("src/fs_ntfs_bootstrap.rs"),
        source!("src/fs_ntfs_compressed.rs"),
        source!("src/fs_ntfs_logfile/checkpoint.rs"),
        source!("src/fs_ntfs_logfile/checkpoint_dumps.rs"),
        source!("src/fs_ntfs_logfile/client_record.rs"),
        source!("src/fs_ntfs_logfile/pages.rs"),
        source!("src/fs_ntfs_logfile/record.rs"),
        source!("src/fs_ntfs_logfile/restart_table.rs"),
        source!("src/fs_ntfs_logfile/table_entries.rs"),
        source!("src/fs_ntfs_logfile.rs"),
        source!("src/fs_ntfs_metadata.rs"),
        source!("src/fs_ntfs_secure.rs"),
        source!("src/fs_ntfs_security.rs"),
        source!("src/fs_ntfs_stream.rs"),
        source!("src/fs_ntfs_tree.rs"),
        source!("src/fs_ntfs_usn.rs"),
        source!("src/fs_ntfs_usn_extract.rs"),
        source!("src/fs_pagination.rs"),
        source!("src/fs_pipeline.rs"),
        source!("src/fs_storage.rs"),
        source!("src/fs_undo.rs"),
        source!("src/fs_xfs.rs"),
        source!("src/fs_xfs_audit.rs"),
        source!("src/fs_xfs_tree.rs"),
        source!("src/gpt.rs"),
        source!("src/guid.rs"),
        source!("src/io.rs"),
        source!("src/layout.rs"),
        source!("src/lib.rs"),
        source!("src/partition.rs"),
        source!("src/payload.rs"),
        source!("src/platform.rs"),
        source!("src/recovery.rs"),
        source!("src/storage.rs"),
        source!("src/uefi.rs"),
        source!("src/volume_probe.rs"),
        source!("tests/bitlocker.rs"),
        source!("tests/bitlocker_native.rs"),
        source!("tests/bitlocker_native_write.rs"),
        source!("tests/bitlocker_tpm.rs"),
        source!("tests/bitlocker_tpm_host.rs"),
        source!("tests/bitlocker_tpm_native.rs"),
        source!("tests/bitlocker_write.rs"),
        source!("tests/codec.rs"),
        source!("tests/common/reader_contract.rs"),
        source!("tests/conversion.rs"),
        source!("tests/conversion_failures.rs"),
        source!("tests/editor.rs"),
        source!("tests/extended.rs"),
        source!("tests/fixtures/apfs_build_tree.rs"),
        source!("tests/fixtures/apfs_cibs.rs"),
        source!("tests/fixtures/apfs_clean.rs"),
        source!("tests/fixtures/apfs_multichunk.rs"),
        source!("tests/fixtures/apfs_queues.rs"),
        source!("tests/fixtures/apfs_repeat.rs"),
        source!("tests/fixtures/apfs_resource.rs"),
        source!("tests/fixtures/bitlocker_vectors.rs"),
        source!("tests/fixtures/ext2_clean.rs"),
        source!("tests/fixtures/fs_ext_legacy_integrity.rs"),
        source!("tests/fixtures/fs_ext_modern.rs"),
        source!("tests/fixtures/hfs_clean.rs"),
        source!("tests/fixtures/hfsplus_clean.rs"),
        source!("tests/fixtures/jffs2_clean.rs"),
        source!("tests/fixtures/jfs_clean.rs"),
        source!("tests/fixtures/ntfs_basic.rs"),
        source!("tests/fixtures/ntfs_clean.rs"),
        source!("tests/fixtures/ntfs_index.rs"),
        source!("tests/fixtures/xfs_clean.rs"),
        source!("tests/fs_apfs.rs"),
        source!("tests/fs_apfs_builder.rs"),
        source!("tests/fs_apfs_builder_cibs.rs"),
        source!("tests/fs_apfs_edit.rs"),
        source!("tests/fs_apfs_edit_cibs.rs"),
        source!("tests/fs_apfs_edit_cibs_controls.rs"),
        source!("tests/fs_apfs_edit_multichunk.rs"),
        source!("tests/fs_apfs_edit_namespace.rs"),
        source!("tests/fs_apfs_edit_namespace_native.rs"),
        source!("tests/fs_apfs_edit_native.rs"),
        source!("tests/fs_apfs_edit_repeat.rs"),
        source!("tests/fs_apfs_queues.rs"),
        source!("tests/fs_apfs_xattr_profiles.rs"),
        source!("tests/fs_copy.rs"),
        source!("tests/fs_core.rs"),
        source!("tests/fs_exfat.rs"),
        source!("tests/fs_exfat_audit.rs"),
        source!("tests/fs_exfat_builder.rs"),
        source!("tests/fs_exfat_copy.rs"),
        source!("tests/fs_exfat_edit.rs"),
        source!("tests/fs_exfat_edit_namespace.rs"),
        source!("tests/fs_exfat_tree.rs"),
        source!("tests/fs_exfat_volume.rs"),
        source!("tests/fs_ext.rs"),
        source!("tests/fs_ext_audit.rs"),
        source!("tests/fs_ext_builder.rs"),
        source!("tests/fs_ext_copy.rs"),
        source!("tests/fs_ext_edit.rs"),
        source!("tests/fs_ext_extent.rs"),
        source!("tests/fs_ext_journal.rs"),
        source!("tests/fs_ext_profiles_native.rs"),
        source!("tests/fs_ext_tree.rs"),
        source!("tests/fs_fat.rs"),
        source!("tests/fs_fat_audit.rs"),
        source!("tests/fs_fat_builder.rs"),
        source!("tests/fs_fat_edit.rs"),
        source!("tests/fs_fat_edit_namespace.rs"),
        source!("tests/fs_fat_tree.rs"),
        source!("tests/fs_file.rs"),
        source!("tests/fs_flash.rs"),
        source!("tests/fs_hfs.rs"),
        source!("tests/fs_hfsplus.rs"),
        source!("tests/fs_image.rs"),
        source!("tests/fs_jffs2.rs"),
        source!("tests/fs_jffs2_builder.rs"),
        source!("tests/fs_jffs2_compression.rs"),
        source!("tests/fs_jffs2_compression_native.rs"),
        source!("tests/fs_jffs2_edit.rs"),
        source!("tests/fs_jffs2_edit_compression_native.rs"),
        source!("tests/fs_jffs2_edit_native.rs"),
        source!("tests/fs_jffs2_native.rs"),
        source!("tests/fs_jfs.rs"),
        source!("tests/fs_ntfs.rs"),
        source!("tests/fs_ntfs_audit.rs"),
        source!("tests/fs_ntfs_audit_resolved.rs"),
        source!("tests/fs_ntfs_audit_resolved_native.rs"),
        source!("tests/fs_ntfs_compressed.rs"),
        source!("tests/fs_ntfs_logfile.rs"),
        source!("tests/fs_ntfs_logfile_checkpoint.rs"),
        source!("tests/fs_ntfs_logfile_checkpoint_entries.rs"),
        source!("tests/fs_ntfs_logfile_checkpoint_links.rs"),
        source!("tests/fs_ntfs_logfile_checkpoint_tables.rs"),
        source!("tests/fs_ntfs_logfile_client_record.rs"),
        source!("tests/fs_ntfs_logfile_dirty_native.rs"),
        source!("tests/fs_ntfs_logfile_native.rs"),
        source!("tests/fs_ntfs_logfile_pages.rs"),
        source!("tests/fs_ntfs_logfile_record.rs"),
        source!("tests/fs_ntfs_logfile_restart_table.rs"),
        source!("tests/fs_ntfs_secure.rs"),
        source!("tests/fs_ntfs_security.rs"),
        source!("tests/fs_ntfs_security_bounds.rs"),
        source!("tests/fs_ntfs_tree.rs"),
        source!("tests/fs_ntfs_usn.rs"),
        source!("tests/fs_ntfs_usn_extract.rs"),
        source!("tests/fs_storage.rs"),
        source!("tests/fs_undo.rs"),
        source!("tests/fs_undo_native.rs"),
        source!("tests/fs_xfs.rs"),
        source!("tests/fs_xfs_native.rs"),
        source!("tests/guid.rs"),
        source!("tests/independent.rs"),
        source!("tests/initialization.rs"),
        source!("tests/layout.rs"),
        source!("tests/no_std.rs"),
        source!("tests/no_std_owned.rs"),
        source!("tests/no_std_readers.rs"),
        source!("tests/partitions.rs"),
        source!("tests/payload.rs"),
        source!("tests/recovery.rs"),
        source!("tests/storage.rs"),
        source!("tests/uefi.rs"),
        source!("tests/upstream_portable_io.rs"),
        source!("tests/volume_probe.rs"),
        source!("src/fs_ext_jbd_foreign_recover.rs"),
        source!("integration/maintenance/ext-foreign-preflight-oracle.py"),
        source!("integration/maintenance/ext-foreign-preflight-qualify.py"),
        source!("integration/maintenance/ext-foreign-cuts-verify.py"),
    ];
    let check_sources = || {
        let mut result = String::new();
        for (name, bytes) in sources {
            assert_eq!(
                fs::read(root.join(name)).unwrap().as_slice(),
                *bytes,
                "compiled source mismatch {name}"
            );
            writeln!(result, "{}  {name}", hash(bytes)).unwrap();
        }
        result
    };
    let source_start = check_sources();
    fs::write(out.join("source-start.sha256"), &source_start).unwrap();
    for (name, bytes) in sources {
        let dest = out.join("compiled-source").join(name);
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::write(dest, bytes).unwrap();
    }
    let binary_path = std::env::current_exe().unwrap();
    let binary = fs::read(&binary_path).unwrap();
    let binary_hash = hash(&binary);
    fs::write(out.join("gate-binary"), binary).unwrap();
    let mut tools = Vec::new();
    for (env, expected) in [
        (
            "PARTMGR_EXT_FOREIGN_MKE2FS",
            "c631499c0c65f780c737164e102f7af76bd6e7f701c4234391fc6173dacbaf03",
        ),
        (
            "PARTMGR_EXT_FOREIGN_DEBUGFS",
            "fdb0c98ec0379bd232ed037de8bbc460a0c16cd1e3094519845837f10a2dea88",
        ),
        (
            "PARTMGR_EXT_FOREIGN_E2FSCK",
            "3ddd3abad8b54577e13877295385a27313e7c1b7fa0165b0e2602280858c24ff",
        ),
    ] {
        let path = required(env);
        check(&path, expected);
        tools.push((path, expected));
    }
    let mut entries: Vec<_> = fs::read_dir(&corpus)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    fs::create_dir(out.join("corpus")).unwrap();
    let mut corpus_start = String::new();
    for path in &entries {
        assert!(path.is_file(), "corpus files only");
        let name = path.file_name().unwrap().to_str().unwrap();
        let bytes = fs::read(path).unwrap();
        let digest = hash(&bytes);
        if name != "receipt.json" {
            assert!(
                receipt_text.contains(&format!("\"{name}\": \"{digest}\"")),
                "unbound corpus artifact {name}"
            );
        } else {
            assert_eq!(bytes, receipt);
        }
        fs::write(out.join("corpus").join(name), bytes).unwrap();
        writeln!(corpus_start, "{digest}  {name}").unwrap();
    }
    fs::write(out.join("corpus-start.sha256"), &corpus_start).unwrap();
    assert_eq!(
        fs::read(corpus.join("oracle-source.py")).unwrap(),
        include_bytes!("../integration/maintenance/ext-foreign-preflight-oracle.py")
    );
    let mut observations = String::new();
    for (bs, dirty_hash, recovered_hash, journal_first) in [
        (
            1024usize,
            "6a5379443d080e0efee7f19bd2fe72cc5337537c1bc510f7db9145cbb71427f1",
            "ae1eca39daffce7a73978a4d2bd3508480c5ab4616ec0db9baeadc47638a6a43",
            274u64,
        ),
        (
            2048,
            "cc28294cfc24311523e51cf2799cd94cc48c2930ba074fe0c308c5c0fb3ca2f3",
            "ae32313d35a06dacde650afd12757c3df24abeeed2d5f34cbb155a02553ac812",
            269,
        ),
        (
            4096,
            "61f0cda549b0e2df60e27f5323a626a64a8ac9d8e97f9fe760af744e677d9e3c",
            "789ec1faa238a2dfcd009310f4c2e3a366c9d98fc296fc7d2cea53cc298a107c",
            137,
        ),
    ] {
        let dirty_path = corpus.join(format!("ext3-b{bs}-dirty.raw"));
        let source = NoWrites {
            bytes: check(&dirty_path, dirty_hash),
            writes: Cell::new(0),
        };
        let native = check(
            &corpus.join(format!("ext3-b{bs}-e2fsck.raw")),
            recovered_hash,
        );
        let r = Resources {
            memory: crate::fs_core::Budget::new(128 << 20),
            cancellation: crate::fs_core::Cancellation::default(),
        };
        let plan = preflight(
            &source,
            18u128 << 64 | bs as u128,
            Limits {
                journal_blocks: 65536,
                bootstrap_work: 32_000_000,
                records: 1024,
                scan_work: 32_000_000,
                audit: ExtAuditLimits {
                    blocks: 65536,
                    inodes: 16384,
                    work: 64_000_000,
                    directory_blocks: 65536,
                    directory_entries: 65536,
                    findings: 1024,
                },
            },
            &r,
        )
        .unwrap();
        assert!(plan.audit.is_clean());
        assert_eq!(plan.geometry.block_size as usize, bs);
        assert_eq!(plan.replay.committed_transactions, 1);
        assert_eq!(plan.replay.next_sequence, 2);
        assert_eq!(plan.restart_sequence, 3);
        assert!(!plan.replay.discarded_tail);
        assert_eq!(plan.replay.blocks.len(), 1);
        assert_eq!(plan.replay.blocks[0].destination, u32::from(bs == 1024));
        assert_eq!(plan.bootstrap.geometry.start, 1);
        assert_eq!(plan.bootstrap.geometry.sequence, 1);
        assert_eq!(
            plan.bootstrap.physical(0).unwrap(),
            journal_first * bs as u64
        );
        for logical in 0..5 {
            assert_eq!(
                plan.bootstrap.physical(logical).unwrap(),
                (journal_first + u64::from(logical)) * bs as u64
            );
        }
        let redo = fs::read(corpus.join(format!("ext3-b{bs}-journal-2.bin"))).unwrap();
        assert_eq!(&plan.replay.blocks[0].bytes[..bs], redo);
        let mut marker = [0; 64];
        let text = format!("partmgr-foreign-preflight-{bs}");
        marker[..text.len()].copy_from_slice(text.as_bytes());
        let inside = if bs == 1024 { 0 } else { 1024 };
        assert_eq!(&redo[inside + 136..inside + 200], marker);
        assert_eq!(&native[1160..1224], marker);
        assert_eq!(super::super::super::u32le(&source.bytes, 1120) & 4, 4);
        assert_eq!(super::super::super::u32le(&native, 1120) & 4, 0);
        let journal_at = journal_first as usize * bs;
        assert_eq!(be32(&native[journal_at..], 24), 3);
        assert_eq!(be32(&native[journal_at..], 28), 0);
        assert_eq!(be32(&plan.empty_journal, 24), 3);
        assert_eq!(be32(&plan.empty_journal, 28), 0);
        assert_eq!(
            &source.bytes[journal_at..journal_at + 1024],
            plan.bootstrap.journal
        );
        for payload in ["payload.bin".to_string(), format!("ext3-b{bs}-payload.bin")] {
            check(
                &corpus.join(payload),
                "c6d5f5c4e150eecbd783ab61b2a5da057bbd0637da2ae7aef3e18f1454ff6d5e",
            );
        }
        plan.check_source(&r).unwrap();
        assert_eq!(source.writes.get(), 0);
        fs::write(out.join(format!("profile-b{bs}-redo.bin")), redo).unwrap();
        fs::write(
            out.join(format!("profile-b{bs}-active-journal.bin")),
            plan.bootstrap.journal,
        )
        .unwrap();
        fs::write(
            out.join(format!("profile-b{bs}-empty-journal.bin")),
            plan.empty_journal,
        )
        .unwrap();
        writeln!(observations, "block_bytes={bs} committed=1 scan_boundary=2 restart_sequence=3 redo_blocks=1 audit_clean=true preflight_writes=0 dirty_sha256={dirty_hash} native_oracle_sha256={recovered_hash}").unwrap();
        drop(plan);
        if recovery {
            let mut target = Writable {
                bytes: source.bytes.clone(),
                writes: 0,
                flushes: 0,
            };
            let recovery_limits = || Limits {
                journal_blocks: 65536,
                bootstrap_work: 32_000_000,
                records: 1024,
                scan_work: 32_000_000,
                audit: ExtAuditLimits {
                    blocks: 65536,
                    inodes: 16384,
                    work: 64_000_000,
                    directory_blocks: 65536,
                    directory_entries: 65536,
                    findings: 1024,
                },
            };
            let outcome = super::recover::recover(
                &mut target,
                18u128 << 64 | bs as u128,
                recovery_limits(),
                &r,
            )
            .unwrap();
            assert_eq!(outcome.transactions, 1);
            assert_eq!(outcome.blocks, 1);
            assert_eq!(outcome.restart_sequence, 3);
            assert_eq!(
                target.bytes, native,
                "entire recovery image must equal independent e2fsprogs output"
            );
            assert!(target.writes > 0 && target.flushes > 0);
            let counts = (target.writes, target.flushes);
            let again = super::recover::recover(
                &mut target,
                18u128 << 64 | bs as u128,
                recovery_limits(),
                &r,
            )
            .unwrap();
            assert_eq!(again.transactions, 0);
            assert_eq!(again.blocks, 0);
            assert_eq!((target.writes, target.flushes), counts);
            assert_eq!(target.bytes, native);
            fs::write(
                out.join(format!("profile-b{bs}-partmgr-recovered.raw")),
                &target.bytes,
            )
            .unwrap();
            writeln!(observations, "block_bytes={bs} recovery_entire_native_image_equal=true writes={} flushes={} clean_retry_writes=0", counts.0, counts.1).unwrap();
        }
        if cut_artifacts {
            cuts::run(&out, bs, &source.bytes, &native, journal_at);
        }
        assert_eq!(r.memory.used(), 0);
        assert_eq!(hash(&source.bytes), dirty_hash);
        check(&dirty_path, dirty_hash);
    }
    let mut corpus_end = String::new();
    for path in &entries {
        writeln!(
            corpus_end,
            "{}  {}",
            hash(&fs::read(path).unwrap()),
            path.file_name().unwrap().to_str().unwrap()
        )
        .unwrap();
    }
    assert_eq!(corpus_end, corpus_start);
    fs::write(out.join("corpus-end.sha256"), corpus_end).unwrap();
    check(
        &receipt_path,
        "d41db945ad24e9fe013fca1a6b0b69e826e03d358eaf8d9f28b491fa730a83de",
    );
    for (path, expected) in tools {
        check(&path, expected);
    }
    assert_eq!(hash(&fs::read(binary_path).unwrap()), binary_hash);
    assert_eq!(check_sources(), source_start);
    fs::write(out.join("source-end.sha256"), check_sources()).unwrap();
    fs::write(out.join("observations.txt"), observations).unwrap();
    fs::write(out.join("receipt.txt"), format!("fixture_receipt_sha256=d41db945ad24e9fe013fca1a6b0b69e826e03d358eaf8d9f28b491fa730a83de\ntest_binary_sha256={binary_hash}\ncompiled_source_manifest=source-start.sha256\ncorpus_manifest=corpus-start.sha256\nprofiles=3\nrecovery={recovery}\ncut_artifacts={cut_artifacts}\npreflight_writes=0\nrecovery_write_counts=observations.txt\n")).unwrap();
    fs::write(out.join("command.txt"), format!("argv={:?}\ncorpus={corpus:?}\nreceipt={receipt_path:?}\nsource_root={root:?}\nevidence={out:?}\n", std::env::args_os().collect::<Vec<_>>())).unwrap();
    let scope = if cut_artifacts {
        "private checksumless foreign recovery simulated durable cuts and Rust cold retry; deduplicated raw cut images require separate e2fsprogs verification; no kernel dirty fixture or public qualification"
    } else if recovery {
        "private checksumless foreign JBD recovery on disposable buffers, exact full-image comparison with independent e2fsprogs replay; no kernel-authored dirty fixture, native crash-recovery or public editor qualification"
    } else {
        "read-only foreign JBD preflight against independently authored footer-free ext3 and separate e2fsprogs replay oracle; no kernel-authored dirty fixture, write recovery, durable crash-recovery or public editor qualification"
    };
    fs::write(
        out.join("report.txt"),
        format!("scope={scope}\nprofiles=3\ncomplete=true\n"),
    )
    .unwrap();
}

struct Writable {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
}
impl Storage for Writable {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(
            self.bytes
                .get(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> io::Result<usize> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(bytes.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        self.bytes
            .get_mut(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(bytes);
        self.writes += 1;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}
