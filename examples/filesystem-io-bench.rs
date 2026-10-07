//! Compare indexed direct file ranges with equivalent logical backend reads.
//! Usage: cargo run --release --example filesystem-io-bench -- IMAGE [OPERATIONS]
use partmgr::fs_file::{ExtentFile, ExtentKind, FileExtent};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use virtdisk::{RawDisk, ReadAt};

struct Counted {
    inner: RawDisk,
    calls: AtomicU64,
    bytes: AtomicU64,
}
impl ReadAt for Counted {
    fn len(&self) -> u64 {
        self.inner.len()
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(out.len() as u64, Ordering::Relaxed);
        self.inner.read_exact_at(offset, out)
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("supply an immutable raw image path")?;
    let operations: usize = args.next().map(|s| s.parse()).transpose()?.unwrap_or(10000);
    if operations == 0 {
        return Err("operations must be positive".into());
    }
    let source = Arc::new(Counted {
        inner: RawDisk::open(path)?,
        calls: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
    });
    if source.len() < 4096 {
        return Err("image must be at least 4096 bytes".into());
    }
    let opened = Instant::now();
    let file = ExtentFile::new(
        source.clone(),
        source.len(),
        vec![FileExtent {
            offset: 0,
            length: source.len(),
            kind: ExtentKind::Data(0),
        }],
        1,
    )?;
    eprintln!(
        "index_validation_ns={}; scratch_bytes=4096; latency_samples={operations}; cache_control=none; image_bytes={}",
        opened.elapsed().as_nanos(),
        source.len()
    );
    println!(
        "access,workload,operations,wall_ns,p50_ns,p95_ns,p99_ns,logical_calls,logical_bytes,checksum"
    );
    for indexed in [false, true] {
        for sequential in [true, false] {
            let mut samples = Vec::with_capacity(operations);
            let mut buffer = [0u8; 4096];
            let mut checksum = 0u64;
            let calls = source.calls.load(Ordering::Relaxed);
            let bytes = source.bytes.load(Ordering::Relaxed);
            let mut random = 0x76e248af19d2u64;
            let start = Instant::now();
            for i in 0..operations {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                let block = if sequential { i as u64 } else { random } % (source.len() / 4096);
                let step = Instant::now();
                if indexed {
                    file.read_at(block * 4096, &mut buffer)?;
                } else {
                    source.read_exact_at(block * 4096, &mut buffer)?;
                }
                samples.push(step.elapsed().as_nanos());
                checksum = checksum.wrapping_add(buffer.iter().map(|v| u64::from(*v)).sum::<u64>());
            }
            let elapsed = start.elapsed().as_nanos();
            samples.sort_unstable();
            println!(
                "{},{},{operations},{elapsed},{},{},{},{},{},{checksum}",
                if indexed { "extent_file" } else { "backend" },
                if sequential {
                    "sequential_4k"
                } else {
                    "random_4k"
                },
                samples[(operations - 1) / 2],
                samples[(operations - 1) * 95 / 100],
                samples[(operations - 1) * 99 / 100],
                source.calls.load(Ordering::Relaxed) - calls,
                source.bytes.load(Ordering::Relaxed) - bytes
            );
        }
    }
    Ok(())
}
