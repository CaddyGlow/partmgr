//! Reproducible APFS metadata and payload workloads over independent native bytes.

use super::{Case, RunMetrics};
use partmgr::{
    fs_apfs::{ApfsContainer, ApfsReadLimits, ApfsVolume},
    fs_apfs_audit::ApfsAuditLimits,
    fs_apfs_edit::{ApfsEditLimits, ApfsEditor},
    fs_core::{Budget, Cancellation, FileRead, NativeName, Resources, StreamKind},
    io::{self, ReadAt},
    storage::Storage,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[allow(dead_code)]
#[path = "../../tests/fixtures/apfs_clean.rs"]
mod fixture;

#[derive(Clone)]
struct Source {
    bytes: Arc<[u8]>,
    reads: Arc<AtomicU64>,
    read_bytes: Arc<AtomicU64>,
}

impl Source {
    fn reset(&self) {
        self.reads.store(0, Ordering::Relaxed);
        self.read_bytes.store(0, Ordering::Relaxed);
    }

    fn metrics(&self, checksum: u64) -> RunMetrics {
        RunMetrics {
            checksum,
            backend_reads: self.reads.load(Ordering::Relaxed),
            backend_bytes: self.read_bytes.load(Ordering::Relaxed),
        }
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        let bytes = self
            .bytes
            .get(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(bytes);
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.read_bytes
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        Ok(())
    }
}

impl ReadAt for Source {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.read(offset, out)
    }
}

impl Storage for Source {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.read(offset, out)
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

fn resources() -> Resources {
    Resources {
        memory: Budget::new(256 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn read_limits() -> ApfsReadLimits {
    ApfsReadLimits {
        blocks: 512,
        checkpoint_blocks: 8,
        objects: 256,
        records: 256,
        work: 64 * 1024 * 1024,
    }
}
fn audit_limits() -> ApfsAuditLimits {
    ApfsAuditLimits {
        blocks: 512,
        objects: 512,
        depth: 32,
        work: 64 * 1024 * 1024,
        findings: 64,
    }
}
fn edit_limits() -> ApfsEditLimits {
    ApfsEditLimits {
        metadata_blocks: 64,
        attempts: 65,
        work: 16 * 1024 * 1024 * 1024,
        read: read_limits(),
        audit: audit_limits(),
    }
}

pub fn cases() -> Vec<Case> {
    let bytes: Arc<[u8]> = fixture::apfs_seed().into();
    let size = bytes.len();
    let mut cases = Vec::new();
    for audited in [false, true] {
        for payload in [false, true] {
            let source = Source {
                bytes: bytes.clone(),
                reads: Arc::new(AtomicU64::new(0)),
                read_bytes: Arc::new(AtomicU64::new(0)),
            };
            let r = resources();
            let container =
                ApfsContainer::open(Arc::new(source.clone()), read_limits(), &r).unwrap();
            let volume = ApfsVolume::open(container, 1026, &r).unwrap();
            let id = volume
                .lookup(&[NativeName::Bytes(b"A\xc3\xa9-file".to_vec())], &r)
                .unwrap();
            let reader = audited.then(|| volume.audited_reader(audit_limits(), &r).unwrap());
            let file = if let Some(reader) = &reader {
                reader.open_stream(&id, &StreamKind::Data, &r).unwrap()
            } else {
                volume.open_file(&id, &r).unwrap()
            };
            let mut expected = [0; 128];
            assert_eq!(file.read_at(0, &mut expected, &r).unwrap(), expected.len());
            for (index, value) in expected.iter().enumerate() {
                assert_eq!(*value, (index * 17 % 251) as u8);
            }
            let name = format!(
                "apfs/{}/{}/native-seed",
                if audited { "audited" } else { "strict" },
                if payload { "read-byte" } else { "open-file" }
            );
            cases.push(Case {
                name,
                size,
                operations: if payload { 128 } else { 1 },
                run: Box::new(move || {
                    source.reset();
                    let mut checksum = 0;
                    if payload {
                        let mut byte = [0];
                        for offset in 0..128 {
                            assert_eq!(file.read_at(offset, &mut byte, &r).unwrap(), 1);
                            checksum += u64::from(std::hint::black_box(byte[0]));
                        }
                    } else {
                        let opened = if let Some(reader) = &reader {
                            reader.open_stream(&id, &StreamKind::Data, &r).unwrap()
                        } else {
                            volume.open_file(&id, &r).unwrap()
                        };
                        checksum = std::hint::black_box(opened.len());
                    }
                    source.metrics(checksum)
                }),
            });
        }
    }
    let source = Source {
        bytes,
        reads: Arc::new(AtomicU64::new(0)),
        read_bytes: Arc::new(AtomicU64::new(0)),
    };
    let r = resources();
    let editor = ApfsEditor::open(source.clone(), 1026, edit_limits(), &r).unwrap();
    assert_eq!(editor.checkpoint_xid(), 1);
    assert!(editor.allocation_proof().is_clean());
    let copied = editor.copied_metadata_blocks();
    drop(editor);
    assert_eq!(r.memory.used(), 0);
    cases.push(Case {
        name: "apfs/owned/prepare/native-seed".into(),
        size,
        operations: 1,
        run: Box::new(move || {
            source.reset();
            let editor = ApfsEditor::open(source.clone(), 1026, edit_limits(), &r).unwrap();
            assert_eq!(editor.copied_metadata_blocks(), copied);
            let checksum = std::hint::black_box(editor.allocation_proof().allocated_blocks());
            drop(editor);
            assert_eq!(r.memory.used(), 0);
            source.metrics(checksum)
        }),
    });
    cases
}
