//! FAT allocation and rendering scaling with fixed image geometry.
use super::{Case, RunMetrics};
use partmgr::{
    fs_core::{Budget, Cancellation, FileRead, Resources},
    fs_fat::{FatFamily, FatVolume},
    fs_fat_builder::{FatBuildFile, FatBuildOptions, FatBuildPlan},
    io::{self, ReadAt},
    storage::Storage,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

const IMAGE_BYTES: usize = 8 * 1024 * 1024;
const FILE_BYTES: usize = 513;

#[derive(Default)]
struct Counters {
    reads: AtomicU64,
    bytes: AtomicU64,
}
impl Counters {
    fn record(&self, n: usize) {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
    fn reset(&self) {
        self.reads.store(0, Ordering::Relaxed);
        self.bytes.store(0, Ordering::Relaxed);
    }
    fn metrics(&self, checksum: u64) -> RunMetrics {
        RunMetrics {
            checksum,
            backend_reads: self.reads.load(Ordering::Relaxed),
            backend_bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}
fn payload(index: usize, offset: usize) -> u8 {
    ((index * 17 + offset) % 251) as u8
}
struct Source {
    index: usize,
    counters: Arc<Counters>,
}
impl ReadAt for Source {
    fn len(&self) -> u64 {
        FILE_BYTES as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| io::ErrorKind::UnexpectedEof)?;
        if start
            .checked_add(out.len())
            .is_none_or(|end| end > FILE_BYTES)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.counters.record(out.len());
        for (n, byte) in out.iter_mut().enumerate() {
            *byte = payload(self.index, start + n);
        }
        Ok(())
    }
}
struct Image {
    bytes: Vec<u8>,
    counters: Arc<Counters>,
}
impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| io::ErrorKind::UnexpectedEof)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        let source = self
            .bytes
            .get(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(source);
        self.counters.record(out.len());
        Ok(())
    }
}
impl Storage for Image {
    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        ReadAt::read_exact_at(self, offset, out)
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        let start = usize::try_from(offset).map_err(|_| io::ErrorKind::UnexpectedEof)?;
        let end = start
            .checked_add(bytes.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        self.bytes
            .get_mut(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn make_resources() -> Resources {
    Resources {
        memory: Budget::new(32 * 1024 * 1024),
        cancellation: Cancellation::default(),
    }
}
fn options() -> FatBuildOptions {
    FatBuildOptions {
        family: FatFamily::Fat16,
        sectors_per_cluster: 1,
        volume_id: 0x42454e43,
    }
}
fn make_files(count: usize, counters: &Arc<Counters>) -> Vec<FatBuildFile> {
    (0..count)
        .map(|index| FatBuildFile {
            name: format!("F{index:07}.BIN"),
            source: Arc::new(Source {
                index,
                counters: counters.clone(),
            }),
        })
        .collect()
}
fn validate(image: Image, count: usize, resources: &Resources) {
    let volume = FatVolume::open(Arc::new(image)).expect("benchmark FAT volume");
    assert_eq!(volume.geometry().family(), FatFamily::Fat16);
    let directory = volume
        .root_directory(4096, 512, resources)
        .expect("benchmark FAT directory");
    assert_eq!(directory.entries().len(), count);
    for (index, entry) in directory.entries().iter().enumerate() {
        let expected_name = format!("F{index:07}BIN");
        assert_eq!(entry.short_name().as_slice(), expected_name.as_bytes());
        let file = volume
            .open_entry(entry, 4096, resources)
            .expect("benchmark FAT file");
        assert_eq!(file.len(), FILE_BYTES as u64);
        let mut actual = [0; FILE_BYTES];
        assert_eq!(
            file.read_at(0, &mut actual, resources)
                .expect("benchmark payload"),
            FILE_BYTES
        );
        for (offset, byte) in actual.into_iter().enumerate() {
            assert_eq!(byte, payload(index, offset));
        }
    }
}

pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for count in [1, 128, 511] {
        let counters = Arc::new(Counters::default());
        let files = make_files(count, &counters);
        let resources = make_resources();
        cases.push(Case {
            name: "fat/plan".into(),
            size: count,
            operations: count as u64,
            run: Box::new(move || {
                counters.reset();
                let plan = FatBuildPlan::new(IMAGE_BYTES as u64, options(), &files, &resources)
                    .expect("benchmark FAT plan");
                std::hint::black_box(&plan);
                counters.metrics(count as u64)
            }),
        });
        let counters = Arc::new(Counters::default());
        let files = make_files(count, &counters);
        let resources = make_resources();
        let plan = FatBuildPlan::new(IMAGE_BYTES as u64, options(), &files, &resources)
            .expect("benchmark FAT plan");
        let mut image = Image {
            bytes: vec![0; IMAGE_BYTES],
            counters: counters.clone(),
        };
        plan.emit(&mut image, &resources)
            .expect("benchmark FAT initial emission");
        validate(image, count, &resources);
        let mut image = Image {
            bytes: vec![0; IMAGE_BYTES],
            counters: counters.clone(),
        };
        cases.push(Case {
            name: "fat/emit-verify".into(),
            size: count,
            operations: IMAGE_BYTES as u64,
            run: Box::new(move || {
                counters.reset();
                let report = plan
                    .emit(&mut image, &resources)
                    .expect("benchmark FAT emission");
                counters.metrics(u64::from_le_bytes(report.sha256[..8].try_into().unwrap()))
            }),
        });
    }
    cases
}
