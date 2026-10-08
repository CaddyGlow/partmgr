use partmgr::{
    fs_core::{Budget, Cancellation, ObjectKind, Resources, TreeSource},
    fs_hfs::{HfsReadLimits, HfsVolume},
    fs_hfs_audit::{HfsAuditLimits, audit_hfs},
    fs_hfs_tree::HfsTreeSource,
};
use std::sync::Arc;
#[path = "../../tests/fixtures/hfs_clean.rs"]
#[allow(dead_code)] // Native-only fragmentation is outside this pure fuzz fixture.
mod fixture;
fn read_limits() -> HfsReadLimits {
    HfsReadLimits {
        blocks: 256,
        nodes: 64,
        records: 128,
        extents: 256,
        work: 2_000_000,
    }
}
fn audit_limits() -> HfsAuditLimits {
    HfsAuditLimits {
        blocks: 256,
        objects: 128,
        depth: 16,
        work: 100_000,
        findings: 32,
    }
}
pub(crate) fn seeds() -> Vec<Vec<u8>> {
    let clean = fixture::hfs_seed();
    let mut lost = clean.clone();
    lost[1536 + 40 / 8] |= 0x80;
    let mut alternate = clean.clone();
    let end = alternate.len();
    alternate[end - 1024] ^= 1;
    let mut geometry = clean.clone();
    geometry[1044..1048].fill(255);
    vec![clean, lost, alternate, geometry, vec![0; 1025]]
}
pub(crate) fn run(data: &[u8]) {
    if data.len() > 1 << 20 {
        return;
    }
    let r = Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    };
    if let Ok(volume) = HfsVolume::open(Arc::new(super::Bytes(data.to_vec())), read_limits(), &r) {
        if let Ok(report) = audit_hfs(&volume, audit_limits(), &r) {
            if !report.is_clean() {
                assert!(report.free_ranges().is_empty());
            }
            for extent in report.free_ranges() {
                assert!(extent.offset >= volume.geometry().allocation_start());
                assert_eq!(
                    (extent.offset - volume.geometry().allocation_start())
                        % u64::from(volume.geometry().block_size()),
                    0
                );
                assert!(extent.offset.checked_add(extent.length).unwrap() <= data.len() as u64);
                assert!(
                    extent.offset + extent.length
                        <= volume.geometry().allocation_start()
                            + u64::from(volume.geometry().blocks())
                                * u64::from(volume.geometry().block_size())
                );
            }
        }
        if let Ok(tree) = HfsTreeSource::inventory(volume, audit_limits(), &r) {
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
    fn independent_profile_reaches_clean_audit_and_resource_forks() {
        {
            let seed = fixture::hfs_seed();
            run(&seed);
            let r = Resources {
                memory: Budget::new(8 << 20),
                cancellation: Cancellation::default(),
            };
            let volume =
                HfsVolume::open(Arc::new(super::super::Bytes(seed)), read_limits(), &r).unwrap();
            assert!(audit_hfs(&volume, audit_limits(), &r).unwrap().is_clean());
            let tree = HfsTreeSource::inventory(volume, audit_limits(), &r).unwrap();
            let page = tree.directory_page(&tree.root(), None, 16, &r).unwrap();
            assert!(page.entries.iter().any(|entry| {
                tree.streams(&entry.object, &r)
                    .is_ok_and(|streams| streams.len() == 2)
            }));
            drop(page);
            drop(tree);
            assert_eq!(r.memory.used(), 0);
        }
    }
}
