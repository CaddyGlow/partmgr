use partmgr::io;
use partmgr::io::ReadAt;
use partmgr::{
    fs_apfs::{ApfsContainer, ApfsReadLimits, ApfsVolume},
    fs_apfs_audit::{ApfsAuditLimits, audit_apfs},
    fs_apfs_tree::ApfsTreeSource,
    fs_core::{Budget, Cancellation, ObjectKind, Resources, TreeSource},
};
use std::sync::Arc;
struct SparseBytes(Vec<u8>);
// Mutable-session decoding must use Storage directly, never an immutable ReadAt
// alias. Preparation and identity lookup must not write or flush malformed input.
struct Preparation(Vec<u8>);
impl partmgr::storage::Storage for Preparation {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(self.0.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        panic!("APFS preparation/identity access attempted mutation");
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("APFS preparation/identity access attempted barrier");
    }
}

fn owned_preparation(data: &[u8]) -> bool {
    use partmgr::fs_apfs_edit::{ApfsEditLimits, ApfsEditor};
    let r = Resources {
        memory: Budget::new(256 << 20),
        cancellation: Cancellation::default(),
    };
    let limits = ApfsEditLimits {
        metadata_blocks: 64,
        attempts: 65,
        work: 16 * 1024 * 1024 * 1024,
        read: ApfsReadLimits {
            blocks: 512,
            checkpoint_blocks: 8,
            ..read_limits()
        },
        audit: ApfsAuditLimits {
            blocks: 512,
            ..audit_limits()
        },
    };
    let mut opened = false;
    if let Ok(editor) = ApfsEditor::open(Preparation(data.to_vec()), 1026, limits, &r) {
        assert!(editor.allocation_proof().is_clean());
        editor.revalidate(&r).unwrap();
        if let Ok(root) = editor.directory_identity(2, &r) {
            opened = true;
            let page = editor.directory(&root, &r).unwrap();
            drop(page);
            let mut stale = root.clone();
            stale.generation ^= 1;
            assert!(editor.directory(&stale, &r).is_err());
            r.cancellation.cancel();
            assert!(editor.directory(&root, &r).is_err());
            assert!(editor.directory_identity(2, &r).is_err());
        }
        let storage = editor.into_storage();
        assert_eq!(storage.0, data);
    }
    assert_eq!(r.memory.used(), 0);
    opened
}
impl ReadAt for SparseBytes {
    fn len(&self) -> u64 {
        if self.0.get(36..40) == Some(&4096u32.to_le_bytes())
            && self.0.get(40..48) == Some(&131073u64.to_le_bytes())
        {
            fixture::MULTIVOLUME_LENGTH
        } else {
            self.0.len() as u64
        }
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        if at
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > self.len())
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        out.fill(0);
        if at < self.0.len() as u64 {
            let start = at as usize;
            let n = out.len().min(self.0.len() - start);
            out[..n].copy_from_slice(&self.0[start..start + n]);
        }
        Ok(())
    }
}
#[path = "../../tests/fixtures/apfs_clean.rs"]
#[allow(dead_code)] // Native-only fragmentation is outside this pure fuzz fixture.
mod fixture;
#[path = "../../tests/fixtures/apfs_queues.rs"]
mod queues;
fn read_limits() -> ApfsReadLimits {
    ApfsReadLimits {
        blocks: 131073,
        checkpoint_blocks: 256,
        objects: 256,
        records: 256,
        work: 64 * 1024 * 1024,
    }
}
fn audit_limits() -> ApfsAuditLimits {
    ApfsAuditLimits {
        blocks: 131073,
        objects: 512,
        depth: 32,
        work: 64 * 1024 * 1024,
        findings: 64,
    }
}
fn open(bytes: Vec<u8>, r: &Resources) -> partmgr::fs_core::Result<ApfsVolume> {
    let container = ApfsContainer::open(Arc::new(SparseBytes(bytes)), read_limits(), r)?;
    let oid = *container.checkpoint().volumes.first().ok_or_else(|| {
        partmgr::fs_core::Error::new(
            partmgr::fs_core::ErrorKind::InvalidData,
            "no fuzz volume candidate",
        )
    })?;
    ApfsVolume::open(container, oid, r)
}
pub(crate) fn seeds() -> Vec<Vec<u8>> {
    let clean = fixture::apfs_seed();
    let mut checksum = clean.clone();
    checksum[100] ^= 1;
    let mut geometry = clean.clone();
    fixture::p32(&mut geometry, 36, 512);
    fixture::seal(&mut geometry[..4096]);
    let mut multiple = clean.clone();
    fixture::second_volume(&mut multiple);
    let mut retained = multiple.clone();
    fixture::next_checkpoint(&mut retained);
    let mut unsupported_unselected = multiple.clone();
    fixture::p64(&mut unsupported_unselected, 50 * 4096 + 264, 0);
    fixture::seal(&mut unsupported_unselected[50 * 4096..51 * 4096]);
    let mut seeds = vec![
        clean,
        checksum,
        geometry,
        vec![0; 35],
        multiple,
        retained,
        unsupported_unselected,
    ];
    seeds.extend(queue_seeds());
    seeds
}
fn queue_seeds() -> Vec<Vec<u8>> {
    let valid = queues::queued_seed();
    let mut count = valid.clone();
    fixture::p64(&mut count, 10 * 4096 + 240, 2);
    fixture::seal(&mut count[10 * 4096..11 * 4096]);
    let mut future = valid.clone();
    future[12 * 4096..13 * 4096].copy_from_slice(&queues::queue(&[(2, 200, 1), (2, 202, 2)], 1029));
    let mut duplicate = valid.clone();
    duplicate[12 * 4096..13 * 4096]
        .copy_from_slice(&queues::queue(&[(1, 200, 2), (1, 201, 2)], 1029));
    let mut domain = valid.clone();
    domain[12 * 4096..13 * 4096].copy_from_slice(&queues::queue(&[(1, 41, 1), (1, 202, 2)], 1029));
    let mut current = valid.clone();
    current[12 * 4096..13 * 4096]
        .copy_from_slice(&queues::queue(&[(1, 100, 1), (1, 202, 2)], 1029));
    let mut ghost = valid.clone();
    fixture::p16(&mut ghost, 12 * 4096 + 58, 65534);
    fixture::seal(&mut ghost[12 * 4096..13 * 4096]);
    let mut free = valid.clone();
    free[41 * 4096 + 200 / 8] &= !(1 << (200 % 8));
    vec![
        valid, count, future, duplicate, domain, current, ghost, free,
    ]
}
pub(crate) fn run(data: &[u8]) {
    if data.len() > 2 << 20 {
        return;
    }
    owned_preparation(data);
    let r = Resources {
        memory: Budget::new(256 << 20),
        cancellation: Cancellation::default(),
    };
    if let Ok(volume) = open(data.to_vec(), &r) {
        if let Ok(report) = audit_apfs(&volume, audit_limits(), &r) {
            if !report.is_clean() {
                assert!(report.free_ranges().is_empty());
            }
            for extent in report.free_ranges() {
                assert_eq!(extent.offset % 4096, 0);
                assert_eq!(extent.length % 4096, 0);
                assert!(
                    extent.offset.checked_add(extent.length).unwrap()
                        <= volume.container().checkpoint().blocks * 4096
                );
            }
        }
        if let Ok(tree) = ApfsTreeSource::inventory(volume, audit_limits(), &r) {
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
    fn owned_preparation_reaches_clean_profile_without_mutation_and_rejects_stale_identity() {
        assert!(owned_preparation(&fixture::apfs_seed()));
        for seed in seeds() {
            owned_preparation(&seed);
        }
    }
    #[test]
    fn unselected_volume_cannot_bypass_container_audit() {
        let seed = seeds().into_iter().nth(6).unwrap();
        run(&seed);
        let r = Resources {
            memory: Budget::new(256 << 20),
            cancellation: Cancellation::default(),
        };
        let volume = open(seed, &r).unwrap();
        let baseline = r.memory.used();
        let error = audit_apfs(&volume, audit_limits(), &r).err().unwrap();
        assert_eq!(error.kind, partmgr::fs_core::ErrorKind::Unsupported);
        assert_eq!(r.memory.used(), baseline);
        drop(volume);
        assert_eq!(r.memory.used(), 0);
    }
    #[test]
    fn multiple_volumes_and_retained_checkpoint_reach_complete_accounting() {
        for seed in seeds().into_iter().skip(4).take(2) {
            run(&seed);
            let r = Resources {
                memory: Budget::new(256 << 20),
                cancellation: Cancellation::default(),
            };
            let container =
                ApfsContainer::open(Arc::new(SparseBytes(seed)), read_limits(), &r).unwrap();
            assert_eq!(container.checkpoint().volumes, vec![1026, 1100]);
            for oid in [1026, 1100] {
                let volume = ApfsVolume::open(container.clone(), oid, &r).unwrap();
                let report = audit_apfs(&volume, audit_limits(), &r).unwrap();
                assert!(report.is_clean());
                assert_eq!(report.allocated_blocks(), 69);
            }
            drop(container);
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[test]
    fn native_ghost_and_explicit_queues_reach_retired_allocation_and_reject_semantic_mutations() {
        for (index, seed) in queue_seeds().into_iter().enumerate() {
            run(&seed);
            let r = Resources {
                memory: Budget::new(256 << 20),
                cancellation: Cancellation::default(),
            };
            let result = open(seed, &r).and_then(|volume| audit_apfs(&volume, audit_limits(), &r));
            if index == 0 {
                let report = result.unwrap();
                assert!(report.is_complete() && report.is_clean());
                assert_eq!(report.allocated_blocks(), 54);
                for block in [200, 202, 203] {
                    assert!(
                        report
                            .free_ranges()
                            .iter()
                            .all(|range| block * 4096 < range.offset
                                || block * 4096 >= range.offset + range.length)
                    );
                }
                drop(report);
            } else if let Ok(report) = result {
                assert!(!report.is_clean(), "mutated queue case{index} accepted");
                assert!(report.free_ranges().is_empty());
                drop(report);
            }
            assert_eq!(r.memory.used(), 0);
        }
    }
    #[test]
    fn independent_profile_reaches_clean_audit_and_resource_fork() {
        {
            let seed = fixture::apfs_seed();
            run(&seed);
            let r = Resources {
                memory: Budget::new(64 << 20),
                cancellation: Cancellation::default(),
            };
            let volume = open(seed, &r).unwrap();
            assert!(audit_apfs(&volume, audit_limits(), &r).unwrap().is_clean());
            let tree = ApfsTreeSource::inventory(volume, audit_limits(), &r).unwrap();
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
