#![cfg(all(feature = "std", unix))]
//! Offline native classic-ext2 same-final-group qualification; no crash claim.
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_ext_audit::ExtAuditLimits,
    fs_ext_edit::{ExtEditBinding, ExtEditLimits, ExtEditRegion, ExtEditState, ExtEditor},
    fs_undo::UndoLimits,
    io,
    storage::Storage,
};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::FileExt, path::PathBuf};
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
struct Disk(fs::File);
impl Storage for Disk {
    fn len(&self) -> io::Result<u64> {
        self.0.metadata().map(|m| m.len()).map_err(Into::into)
    }
    fn read_exact_at(&self, at: u64, b: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(b, at).map_err(Into::into)
    }
    fn write_at(&mut self, at: u64, b: &[u8]) -> io::Result<usize> {
        self.0.write_at(b, at).map_err(Into::into)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.sync_all().map_err(Into::into)
    }
}
fn required(n: &str) -> PathBuf {
    let p = PathBuf::from(std::env::var_os(n).expect(n));
    assert!(p.is_absolute());
    p
}
#[test]
#[ignore = "requires pinned native v5 corpus and fresh evidence directory"]
fn native_same_final_group_ext2_grow() {
    let root = required("PARTMGR_GATE_SOURCE_ROOT");
    let corpus = required("PARTMGR_EXT_GROW_CORPUS");
    let out = required("PARTMGR_EXT_GROW_EVIDENCE");
    fs::create_dir(&out).unwrap();
    assert_eq!(
        digest(&fs::read(corpus.join("receipt.json")).unwrap()),
        "ff88372ea8bfcd8e2a070587e4a31ce4331ff12478aa49f8b0a02520abe68ca9"
    );
    macro_rules! source {
        ($p:literal) => {
            ($p, include_bytes!(concat!("../", $p)).as_slice())
        };
    }
    let sources: &[(&str, &[u8])] = &[
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
        source!("src/fs_ext_edit_geometry.rs"),
        source!("src/fs_ext_edit_namespace.rs"),
        source!("src/fs_ext_edit_ordered_tests.rs"),
        source!("src/fs_ext_jbd_ordered_tests.rs"),
        source!("src/fs_ext_edit_transaction.rs"),
        source!("src/fs_ext_extent.rs"),
        source!("src/fs_ext_hash.rs"),
        source!("src/fs_ext_integrity.rs"),
        source!("src/fs_ext_jbd.rs"),
        source!("src/fs_ext_jbd_bootstrap.rs"),
        source!("src/fs_ext_jbd_foreign.rs"),
        source!("src/fs_ext_jbd_foreign_native.rs"),
        source!("src/fs_ext_jbd_foreign_native_cuts.rs"),
        source!("src/fs_ext_jbd_foreign_recover.rs"),
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
        source!("src/fs_ext_jbd_owned_native_cuts.rs"),
        source!("src/fs_ext_jbd_recovery.rs"),
        source!("src/fs_ext_jbd_session.rs"),
        source!("src/fs_ext_owned.rs"),
        source!("tests/fs_ext_owned.rs"),
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
        source!("src/fs_maintenance_format.rs"),
        source!("src/fs_maintenance_format_tests.rs"),
        source!("src/fs_ntfs.rs"),
        source!("src/fs_ntfs_audit.rs"),
        source!("src/fs_ntfs_bootstrap.rs"),
        source!("src/fs_ntfs_compressed.rs"),
        source!("src/fs_ntfs_logfile/checkpoint.rs"),
        source!("src/fs_ntfs_logfile/checkpoint_dumps.rs"),
        source!("src/fs_ntfs_logfile/client_record.rs"),
        source!("src/fs_ntfs_logfile/pages.rs"),
        source!("src/fs_ntfs_logfile/record.rs"),
        source!("src/fs_ntfs_logfile/record_links.rs"),
        source!("src/fs_ntfs_logfile/restart_selection.rs"),
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
        source!("Cargo.toml"),
        source!("Cargo.lock"),
        source!("tests/fs_ext_geometry_grow_native.rs"),
        source!("integration/maintenance/ext-grow-qualify.py"),
    ];
    let snapshot = || {
        let mut s = String::new();
        for (name, b) in sources {
            assert_eq!(fs::read(root.join(name)).unwrap(), *b, "source {name}");
            s.push_str(&format!("{} {name}\n", digest(b)));
        }
        s
    };
    let before = snapshot();
    fs::write(out.join("source-start.sha256"), &before).unwrap();
    for (name, b) in sources {
        let p = out.join("compiled-source").join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b).unwrap();
    }
    fs::copy(std::env::current_exe().unwrap(), out.join("gate-binary")).unwrap();
    let models = &[
        (
            1024u32,
            2049u32,
            "2772d7470b26e4102374835d0cebed1575f86a57f510767fcbbf35a10de07951",
        ),
        (
            2048u32,
            2048u32,
            "7c129f50f82c08efeafffc73d119798fc4d2623f7b8a01bd05bb094fc0fce148",
        ),
        (
            4096u32,
            2048u32,
            "1228e5c664a19067d9ce86e8f8594da92a76a2fac9ab93ab17cca0bcb756f366",
        ),
    ];
    let mut rows = Vec::new();
    for &(bs, new_blocks, input_hash) in models {
        let input = fs::read(corpus.join(format!("ext2-b{bs}-extended-before.raw"))).unwrap();
        assert_eq!(digest(&input), input_hash);
        let path = out.join(format!("ext2-b{bs}.raw"));
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(input.len() as u64).unwrap();
        file.write_all_at(&input, 0).unwrap();
        file.sync_all().unwrap();
        let journal = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(out.join(format!("ext2-b{bs}.undo")))
            .unwrap();
        journal.set_len(1 << 20).unwrap();
        journal.sync_all().unwrap();
        let r = Resources {
            memory: Budget::new(64 << 20),
            cancellation: Cancellation::default(),
        };
        let limits = ExtEditLimits {
            audit: ExtAuditLimits {
                blocks: 32768,
                inodes: 32768,
                work: 8_000_000,
                directory_blocks: 1024,
                directory_entries: 4096,
                findings: 64,
            },
            file_blocks: 32768,
            directory_entries: 4096,
            affected_bytes: 1 << 20,
            work: 1_000_000,
            undo: UndoLimits {
                patches: 256,
                body_bytes: 1 << 19,
            },
        };
        let mut editor = ExtEditor::open(
            Disk(file),
            Disk(journal),
            ExtEditRegion {
                offset: 0,
                length: u64::from(bs) * u64::from(new_blocks),
            },
            ExtEditBinding {
                volume: Sha256::digest(&input).into(),
                generation: 1,
            },
            limits,
            &r,
        )
        .unwrap();
        let (batch, report) = editor.plan_grow_filesystem(new_blocks, &r).unwrap();
        assert_eq!(report.added_free_blocks, 768);
        assert_eq!(report.groups, 2);
        assert_eq!(report.block_size, bs);
        editor.commit(batch, [bs as u8 + 1; 16], &r).unwrap();
        assert_eq!(editor.state(), ExtEditState::Ready);
        assert_eq!(editor.geometry().blocks(), new_blocks);
        assert!(editor.audit().unwrap().is_clean());
        drop(editor);
        let actual = fs::read(&path).unwrap();
        assert_eq!(actual.len(), input.len());
        assert_eq!(&actual[..64], &input[..64]);
        assert_eq!(
            &actual[bs as usize * new_blocks as usize..],
            &input[bs as usize * new_blocks as usize..]
        );
        assert_eq!(r.memory.used(), 0);
        rows.push(format!(
            "{{\"block_bytes\":{bs},\"blocks\":{new_blocks},\"sha256\":\"{}\"}}",
            digest(&actual)
        ));
        assert_eq!(
            digest(&fs::read(corpus.join(format!("ext2-b{bs}-extended-before.raw"))).unwrap()),
            input_hash
        );
    }
    assert_eq!(snapshot(), before);
    fs::write(out.join("source-end.sha256"), snapshot()).unwrap();
    fs::write(
        out.join("report.json"),
        format!("{{\"complete\":true,\"profiles\":[{}]}}\n", rows.join(",")),
    )
    .unwrap();
}
