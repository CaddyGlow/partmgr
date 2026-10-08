use partmgr::{
    fs_core::{Budget, Cancellation, ObjectKind, Resources, TreeSource},
    fs_jfs::{JfsReadLimits, JfsVolume},
    fs_jfs_audit::{JfsAuditLimits, audit_jfs},
    fs_jfs_tree::JfsTreeSource,
};
use std::sync::Arc;
#[path = "../../tests/fixtures/jfs_clean.rs"]
#[allow(dead_code)] // Native-only fragmentation is outside this pure fuzz fixture.
mod fixture;
fn read_limits() -> JfsReadLimits {
    JfsReadLimits {
        blocks: 65536,
        inodes: 512,
        entries: 1024,
        pages: 1024,
        extents: 4096,
        work: 64 * 1024 * 1024,
    }
}
fn audit_limits() -> JfsAuditLimits {
    JfsAuditLimits {
        blocks: 65536,
        objects: 1024,
        depth: 32,
        work: 1_000_000,
        findings: 64,
    }
}
pub(crate) fn seeds() -> Vec<Vec<u8>> {
    let clean = fixture::jfs_seed();
    let mut log = clean.clone();
    fixture::p32(&mut log, 483 * fixture::BLOCK + 28, 0);
    let mut mirror = clean.clone();
    mirror[61440 + 36] ^= 1;
    let mut geometry = clean.clone();
    fixture::p32(&mut geometry, 32768 + 16, 512);
    vec![clean, log, mirror, geometry, vec![0; 32771]]
}
pub(crate) fn run(data: &[u8]) {
    if data.len() > 2 << 20 {
        return;
    }
    let r = Resources {
        memory: Budget::new(32 << 20),
        cancellation: Cancellation::default(),
    };
    if let Ok(volume) = JfsVolume::open(Arc::new(super::Bytes(data.to_vec())), read_limits(), &r) {
        if let Ok(report) = audit_jfs(&volume, audit_limits(), &r) {
            if !report.is_clean() {
                assert!(report.free_ranges().is_empty());
            }
            for extent in report.free_ranges() {
                assert_eq!(extent.offset % 4096, 0);
                assert_eq!(extent.length % 4096, 0);
                assert!(
                    extent.offset.checked_add(extent.length).unwrap()
                        <= volume.geometry().allocation_blocks() * 4096
                );
            }
        }
        if let Ok(tree) = JfsTreeSource::inventory(volume, audit_limits(), &r) {
            let mut directories = vec![tree.root()];
            let mut retained = Vec::new();
            for _ in 0..8 {
                let Some(directory) = directories.pop() else {
                    break;
                };
                let _ = tree.metadata(&directory, &r);
                if let Ok(page) = tree.directory_page(&directory, None, 16, &r) {
                    for entry in &page.entries {
                        let _ = tree.metadata(&entry.object, &r);
                        if let Ok(streams) = tree.streams(&entry.object, &r) {
                            for stream in streams.iter().take(4) {
                                if let Ok(file) = tree.open_stream(&entry.object, &stream.kind, &r)
                                {
                                    let mut out = [0; 73];
                                    for at in [0, 4095, file.len(), u64::MAX] {
                                        if let Ok(n) = file.read_at(at, &mut out, &r) {
                                            assert!(n <= out.len());
                                            if at >= file.len() {
                                                assert_eq!(n, 0);
                                            }
                                        }
                                    }
                                    let _ = file.visit_extents(&r, &mut |_| Ok(()));
                                    if retained.len() < 16 {
                                        retained.push(file);
                                    }
                                }
                            }
                        }
                        if entry.kind == ObjectKind::Directory && directories.len() < 16 {
                            directories.push(entry.object.clone());
                        }
                    }
                    if let Some(next) = &page.next {
                        let _ = tree.directory_page(&directory, Some(next), 16, &r);
                    }
                }
            }
            drop(tree);
            r.cancellation.cancel();
            for file in &retained {
                assert!(file.read_at(file.len(), &mut [], &r).is_err());
            }
        }
    }
    assert_eq!(r.memory.used(), 0);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_profile_reaches_clean_audit_and_data_stream() {
        {
            let seed = fixture::jfs_seed();
            run(&seed);
            let r = Resources {
                memory: Budget::new(32 << 20),
                cancellation: Cancellation::default(),
            };
            let volume =
                JfsVolume::open(Arc::new(super::super::Bytes(seed)), read_limits(), &r).unwrap();
            assert!(audit_jfs(&volume, audit_limits(), &r).unwrap().is_clean());
            let tree = JfsTreeSource::inventory(volume, audit_limits(), &r).unwrap();
            let page = tree.directory_page(&tree.root(), None, 16, &r).unwrap();
            assert!(page.entries.iter().any(|entry| {
                tree.streams(&entry.object, &r)
                    .is_ok_and(|streams| streams.len() == 1)
            }));
            drop(page);
            drop(tree);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
