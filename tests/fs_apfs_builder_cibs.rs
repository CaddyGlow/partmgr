use partmgr::{fs_apfs_builder::*, fs_core::*};
use std::sync::{Arc, atomic::Ordering};
#[allow(dead_code)]
#[path = "fixtures/apfs_build_tree.rs"]
mod tree;
const BLOCKS: u64 = 126 * 32768 + 2048;
fn options(blocks: u64) -> ApfsBuildOptions {
    ApfsBuildOptions {
        image_bytes: blocks * 4096,
        container_uuid: [0x61; 16],
        volume_uuid: [0x71; 16],
        volume_label: b"Two CIB planning".to_vec(),
        names: ApfsBuildNames::ExactBytes,
        metadata: ApfsBuildMetadata::ContentOnlyDefaults(ApfsBuildDefaults {
            uid: 0,
            gid: 0,
            file_permissions: 0o644,
            directory_permissions: 0o755,
            timestamp: 123456789,
        }),
        limits: ApfsBuildLimits {
            objects: 32,
            occurrences: 64,
            name_bytes: 8192,
            depth: 8,
            blocks,
            work: 64 * 1024 * 1024,
            page_entries: 2,
        },
    }
}
#[test]
fn two_cib_planning_is_deferred_and_refunds_bounded_geometry() {
    let r = Resources {
        memory: Budget::new(8 * 1024 * 1024 * 1024),
        cancellation: Cancellation::default(),
    };
    let source = Arc::new(tree::Tree::new(3));
    let plan = ApfsBuildPlan::plan_with_checkpoint_capacity(
        source.clone(),
        options(BLOCKS),
        ApfsCheckpointCapacity {
            descriptor_blocks: 32,
            data_blocks: 64,
        },
        &r,
    )
    .unwrap();
    assert_eq!(plan.image_bytes(), BLOCKS * 4096);
    assert_eq!(source.controls.reads.load(Ordering::Acquire), 0);
    assert!(r.memory.used() > 0);
    drop(plan);
    assert_eq!(r.memory.used(), 0);
}
#[test]
fn beyond_127_chunk_profile_and_insufficient_memory_refuse_before_payload_reads() {
    for (blocks, memory) in [(127 * 32768 + 1, 8 * 1024 * 1024 * 1024), (BLOCKS, 1024)] {
        let r = Resources {
            memory: Budget::new(memory),
            cancellation: Cancellation::default(),
        };
        let source = Arc::new(tree::Tree::new(3));
        assert!(ApfsBuildPlan::plan(source.clone(), options(blocks), &r).is_err());
        assert_eq!(source.controls.reads.load(Ordering::Acquire), 0);
        assert_eq!(r.memory.used(), 0);
    }
}
