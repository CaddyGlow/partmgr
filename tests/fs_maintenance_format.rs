#![cfg(feature = "std")]
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_ext_audit::ExtAuditLimits,
    fs_ext_builder::{ExtBuildLimits, ExtBuildMetadata, ExtBuildOptions},
    fs_maintenance_format::{ExtFormatImage, ExtFormatLimits, ExtFormatState},
};
#[test]
fn public_new_working_image_requires_complete_verification() {
    let root =
        std::env::temp_dir().join(format!("partmgr-public-ext-format-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    for bs in [1024, 2048, 4096] {
        let path = root.join(format!("b{bs}.working"));
        let mut image = ExtFormatImage::create_new(&path, 16 << 20, &r).unwrap();
        let limits = ExtFormatLimits {
            zero_scan_bytes: 16 << 20,
            build: ExtBuildLimits {
                objects: 4,
                links: 4,
                name_bytes: 1024,
                blocks: 32768,
                work: 4_000_000,
                depth: 8,
            },
            audit: ExtAuditLimits {
                blocks: 32768,
                inodes: 32768,
                work: 8_000_000,
                directory_blocks: 1024,
                directory_entries: 1024,
                findings: 64,
            },
        };
        let report = image
            .plan_empty(
                ExtBuildOptions {
                    block_size: bs,
                    blocks_per_group: bs * 8,
                    uuid: [0x39; 16],
                },
                ExtBuildMetadata {
                    file_permissions: 0o644,
                    directory_permissions: 0o755,
                    uid: 0,
                    gid: 0,
                    timestamp: 946684800,
                },
                limits,
                &r,
            )
            .unwrap()
            .emit(&r)
            .unwrap();
        assert_eq!(image.state(), ExtFormatState::Verified);
        assert!(report.audit.is_clean());
        assert_eq!(report.block_size, bs);
        assert_eq!(report.uuid, [0x39; 16]);
        assert_eq!(report.build.files, 0);
        let artifact = image.into_verified().unwrap();
        assert_eq!(artifact.working_path, path);
        assert_eq!(artifact.file.metadata().unwrap().len(), 16 << 20);
        drop(artifact);
        drop(report);
        assert_eq!(r.memory.used(), 0);
    }
}
