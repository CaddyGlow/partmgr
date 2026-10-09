use partmgr::io;
use partmgr::{
    fs_core::{
        Budget, Cancellation, ExtentKind, FileRead, LogicalExtent, ObjectId, Resources, StreamKind,
        TreeSource,
    },
    fs_flash::{FlashImage, FlashLimits},
    fs_jffs2::{Jffs2CompressionLimits, Jffs2Endian, Jffs2Volume},
    fs_jffs2_builder::Jffs2BuildCompression,
    fs_jffs2_edit::{
        Jffs2CreateMetadata, Jffs2EditCompression, Jffs2EditLimits, Jffs2Editor, recover,
        recover_compressed,
    },
    fs_jffs2_tree::Jffs2TreeSource,
    storage::Storage,
};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct Backend(Arc<Mutex<Vec<u8>>>, Arc<AtomicUsize>);
impl Backend {
    fn new(bytes: Arc<Mutex<Vec<u8>>>) -> Self {
        Self(bytes, Arc::new(AtomicUsize::new(0)))
    }
}
struct Payload {
    id: ObjectId,
    bytes: Vec<u8>,
}
impl FileRead for Payload {
    fn identity(&self) -> &ObjectId {
        &self.id
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, at: u64, out: &mut [u8], r: &Resources) -> partmgr::fs_core::Result<usize> {
        r.cancellation.check()?;
        let n = self.len().saturating_sub(at).min(out.len() as u64) as usize;
        if n != 0 {
            out[..n].copy_from_slice(&self.bytes[at as usize..at as usize + n]);
        }
        Ok(n)
    }
    fn visit_extents(
        &self,
        r: &Resources,
        visit: &mut dyn FnMut(LogicalExtent) -> partmgr::fs_core::Result<()>,
    ) -> partmgr::fs_core::Result<()> {
        r.cancellation.check()?;
        if !self.bytes.is_empty() {
            visit(LogicalExtent {
                offset: 0,
                length: self.len(),
                kind: ExtentKind::Data,
            })?;
        }
        Ok(())
    }
}

pub(crate) fn run_range(data: &[u8], endian: Jffs2Endian) -> bool {
    run_range_profile(data, endian, None)
}
pub(crate) fn run_compressed_range(
    data: &[u8],
    endian: Jffs2Endian,
    codec: Jffs2BuildCompression,
) -> bool {
    run_range_profile(
        data,
        endian,
        Some(Jffs2EditCompression {
            codec,
            read: Jffs2CompressionLimits {
                compressed_node_bytes: 4096,
                decoded_node_bytes: 4096,
                compressed_bytes: 1 << 20,
                decoded_bytes: 1 << 20,
                work: 2 << 20,
            },
        }),
    )
}
fn run_range_profile(
    data: &[u8],
    endian: Jffs2Endian,
    compression: Option<Jffs2EditCompression>,
) -> bool {
    if data.len() > 1 << 20 {
        return false;
    }
    let r = Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    };
    let completed = (|| {
        let mut bytes = data.to_vec();
        if bytes.len().is_multiple_of(4096) {
            bytes.resize(bytes.len().max(65536), 255);
        }
        let volume = open_volume(bytes.clone(), endian, compression, &r).ok()?;
        let original = volume.open_file(2, &r).ok()?;
        if original.len() > if compression.is_some() { 2048 } else { 64 } {
            return None;
        }
        let mut expected = vec![0; original.len() as usize];
        assert_eq!(original.read_at(0, &mut expected, &r).ok()?, expected.len());
        drop((original, volume));
        let state = Arc::new(Mutex::new(bytes));
        let target_backend = Backend::new(state.clone());
        let target_writes = target_backend.1.clone();
        let flash = FlashImage::new(
            target_backend,
            super::jffs2::geometry(),
            &[],
            FlashLimits {
                bad_blocks: 0,
                operation_bytes: 8192,
                scratch_bytes: 128,
            },
            &r,
        )
        .ok()?;
        let limits = Jffs2EditLimits {
            read: super::jffs2::limits(),
            audit: super::jffs2::audit_limits(),
            journal_bytes: 32768,
            slots: 32,
            file_bytes: 64,
            scratch_bytes: 128,
        };
        let mut editor = if let Some(profile) = compression {
            Jffs2Editor::open_compressed(flash, [38; 32], endian, limits, profile, &r)
        } else {
            Jffs2Editor::open(flash, [38; 32], endian, limits, &r)
        }
        .ok()?;
        let old = editor.identity(2).ok()?;
        let payload = Payload {
            id: ObjectId {
                source: 99,
                generation: 1,
                native: vec![7],
            },
            bytes: data[..data.len().min(160)].to_vec(),
        };
        let final_length = 8 + payload.len();
        let plan = editor
            .write_range(&old, 8, &payload, final_length, 11, &r)
            .ok()?;
        let mut journal = Backend::new(Arc::new(Mutex::new(vec![0; 32768])));
        let report = editor.commit(plan, &mut journal, &r).ok()?;
        assert_eq!(report.accepted_bytes, report.verified_bytes);
        assert!(
            editor
                .write_range(&old, 8, &payload, final_length, 12, &r)
                .is_err()
        );
        expected.resize(final_length as usize, 0);
        expected[8..].copy_from_slice(&payload.bytes);
        let mut flash = editor.into_flash();
        let target_before = state.lock().unwrap().clone();
        let journal_before = journal.0.lock().unwrap().clone();
        let target_writes_before = target_writes.load(Ordering::Relaxed);
        let journal_writes_before = journal.1.load(Ordering::Relaxed);
        if let Some(profile) = compression {
            assert!(recover(&mut flash, &mut journal, [38; 32], endian, limits, &r).is_err());
            assert_eq!(*state.lock().unwrap(), target_before);
            assert_eq!(*journal.0.lock().unwrap(), journal_before);
            assert_eq!(target_writes.load(Ordering::Relaxed), target_writes_before);
            assert_eq!(journal.1.load(Ordering::Relaxed), journal_writes_before);
            let mismatched = Jffs2EditCompression {
                read: Jffs2CompressionLimits {
                    work: profile.read.work + 1,
                    ..profile.read
                },
                ..profile
            };
            assert!(
                recover_compressed(
                    &mut flash,
                    &mut journal,
                    [38; 32],
                    endian,
                    limits,
                    mismatched,
                    &r
                )
                .is_err()
            );
            assert_eq!(target_writes.load(Ordering::Relaxed), target_writes_before);
            assert_eq!(journal.1.load(Ordering::Relaxed), journal_writes_before);
            let mut malformed = journal_before.clone();
            let unknown_codec = 0x100u32 | u32::from(data.first().copied().unwrap_or(0));
            for base in [0, 512] {
                malformed[base + 236..base + 240].copy_from_slice(&unknown_codec.to_le_bytes());
                let digest = Sha256::digest(&malformed[base..base + 480]);
                malformed[base + 480..base + 512].copy_from_slice(&digest);
            }
            let malformed_state = Arc::new(Mutex::new(malformed.clone()));
            let mut malformed_journal = Backend::new(malformed_state.clone());
            assert!(
                recover_compressed(
                    &mut flash,
                    &mut malformed_journal,
                    [38; 32],
                    endian,
                    limits,
                    profile,
                    &r
                )
                .is_err()
            );
            assert_eq!(target_writes.load(Ordering::Relaxed), target_writes_before);
            assert_eq!(malformed_journal.1.load(Ordering::Relaxed), 0);
            assert_eq!(*malformed_state.lock().unwrap(), malformed);
            assert_eq!(*state.lock().unwrap(), target_before);
            let restored = recover_compressed(
                &mut flash,
                &mut journal,
                [38; 32],
                endian,
                limits,
                profile,
                &r,
            )
            .unwrap();
            assert_eq!(restored.sha256, report.sha256);
        } else {
            let restored = recover(&mut flash, &mut journal, [38; 32], endian, limits, &r).unwrap();
            assert_eq!(restored.sha256, report.sha256);
        }
        assert_eq!(*state.lock().unwrap(), target_before);
        assert_eq!(*journal.0.lock().unwrap(), journal_before);
        assert_eq!(target_writes.load(Ordering::Relaxed), target_writes_before);
        assert_eq!(journal.1.load(Ordering::Relaxed), journal_writes_before);
        drop(flash);
        let volume = open_volume(state.lock().unwrap().clone(), endian, compression, &r).unwrap();
        let file = volume.open_file(2, &r).unwrap();
        let identity = file.identity().clone();
        let mut actual = vec![0xaa; expected.len()];
        assert_eq!(file.len(), expected.len() as u64);
        assert_eq!(file.read_at(0, &mut actual, &r).unwrap(), actual.len());
        assert_eq!(actual, expected);
        let tree = Jffs2TreeSource::inventory(volume, super::jffs2::audit_limits(), &r).unwrap();
        let page = tree.directory_page(&tree.root(), None, 32, &r).unwrap();
        for entry in &page.entries {
            if entry.object.native == identity.native {
                assert_eq!(entry.object, identity);
            }
            if entry.kind == partmgr::fs_core::ObjectKind::Directory
                && let Ok(child) = tree.directory_page(&entry.object, None, 16, &r)
            {
                for alias in &child.entries {
                    if alias.object.native == identity.native {
                        assert_eq!(alias.object, identity);
                    }
                }
            }
        }
        Some(())
    })()
    .is_some();
    assert_eq!(r.memory.used(), 0);
    completed
}

fn open_volume(
    bytes: Vec<u8>,
    endian: Jffs2Endian,
    compression: Option<Jffs2EditCompression>,
    r: &Resources,
) -> partmgr::fs_core::Result<Jffs2Volume> {
    let source = Arc::new(super::Bytes(bytes));
    if let Some(profile) = compression {
        Jffs2Volume::open_compressed(
            source,
            super::jffs2::geometry(),
            endian,
            super::jffs2::limits(),
            profile.read,
            r,
        )
    } else {
        Jffs2Volume::open(
            source,
            super::jffs2::geometry(),
            endian,
            super::jffs2::limits(),
            r,
        )
    }
}

impl Storage for Backend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().len() as u64)
    }
    fn read_exact_at(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let bytes = self.0.lock().unwrap();
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(bytes.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
    fn write_at(&mut self, at: u64, input: &[u8]) -> io::Result<usize> {
        self.1.fetch_add(1, Ordering::Relaxed);
        let mut bytes = self.0.lock().unwrap();
        let start = usize::try_from(at).map_err(io::Error::other)?;
        let n = input.len().min(7);
        let end = start.checked_add(n).ok_or(io::ErrorKind::UnexpectedEof)?;
        bytes
            .get_mut(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(&input[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Exclusive mutable ownership ends before an immutable deferred reader is created.
pub(crate) fn run(data: &[u8], endian: Jffs2Endian) -> bool {
    let _ = run_range(data, endian);
    if data.len() > 1 << 20 {
        return false;
    }
    let r = Resources {
        memory: Budget::new(8 << 20),
        cancellation: Cancellation::default(),
    };
    let state = Arc::new(Mutex::new(data.to_vec()));
    let completed = (|| {
        let flash = FlashImage::new(
            Backend::new(state.clone()),
            super::jffs2::geometry(),
            &[],
            FlashLimits {
                bad_blocks: 0,
                operation_bytes: 8192,
                scratch_bytes: 128,
            },
            &r,
        )
        .ok()?;
        let limits = Jffs2EditLimits {
            read: super::jffs2::limits(),
            audit: super::jffs2::audit_limits(),
            journal_bytes: 32768,
            slots: 32,
            file_bytes: 64,
            scratch_bytes: 128,
        };
        let mut editor = Jffs2Editor::open(flash, [37; 32], endian, limits, &r).ok()?;
        let root = editor.identity(1).ok()?;
        let payload = &data[..data.len().min(32)];
        let metadata = Jffs2CreateMetadata {
            permissions: 0o640,
            uid: 123,
            gid: 456,
            accessed: 7,
            modified: 8,
            changed: 9,
        };
        let plan = editor
            .create_file(&root, b"fuzz-owned", payload, metadata, &r)
            .ok()?;
        let journal = Arc::new(Mutex::new(vec![0; 32768]));
        let report = editor.commit(plan, &mut Backend::new(journal), &r).ok()?;
        assert_eq!(report.accepted_bytes, report.verified_bytes);
        assert!(!report.mutation_uncertain);
        assert!(
            editor
                .create_file(&root, b"stale", payload, metadata, &r)
                .is_err()
        );
        drop(editor);
        let bytes = state.lock().unwrap().clone();
        let volume = Jffs2Volume::open(
            Arc::new(super::Bytes(bytes)),
            super::jffs2::geometry(),
            endian,
            super::jffs2::limits(),
            &r,
        )
        .unwrap();
        let tree = Jffs2TreeSource::inventory(volume, super::jffs2::audit_limits(), &r).unwrap();
        let page = tree.directory_page(&tree.root(), None, 32, &r).unwrap();
        let entry = page
            .entries
            .iter()
            .find(|e| {
                matches!(&e.name,
            partmgr::fs_core::NativeName::Bytes(name) if name == b"fuzz-owned")
            })
            .unwrap();
        let file = tree
            .open_stream(&entry.object, &StreamKind::Data, &r)
            .unwrap();
        assert_eq!(file.len(), payload.len() as u64);
        let mut actual = [0; 64];
        let n = file.read_at(0, &mut actual, &r).unwrap();
        assert_eq!(&actual[..n], payload);
        Some(())
    })()
    .is_some();
    assert_eq!(r.memory.used(), 0);
    completed
}

#[test]
fn independent_seed_reaches_owned_create_short_program_and_reopen() {
    for (big, endian) in [(false, Jffs2Endian::Little), (true, Jffs2Endian::Big)] {
        assert!(run(&super::jffs2::seeds()[usize::from(big)], endian));
    }
}

#[test]
fn independent_seed_reaches_multi_node_shared_inode_range_and_zero_gap() {
    for (big, endian) in [(false, Jffs2Endian::Little), (true, Jffs2Endian::Big)] {
        assert!(run_range(&super::jffs2::seeds()[usize::from(big)], endian));
    }
}

#[test]
fn independent_rtime_history_reaches_both_owned_codecs_and_bound_complete_recovery() {
    let seeds = super::jffs2::seeds();
    for (index, endian) in [(7, Jffs2Endian::Little), (8, Jffs2Endian::Big)] {
        for codec in [Jffs2BuildCompression::Rtime, Jffs2BuildCompression::Zlib] {
            assert!(run_compressed_range(&seeds[index], endian, codec));
        }
    }
}
