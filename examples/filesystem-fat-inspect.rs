//! Inspect FAT geometry and optionally stream an explicitly identified file chain.
//! This does not perform namespace decoding or a whole-volume ownership audit.
use partmgr::{
    fs_core::{Budget, Cancellation, Resources},
    fs_fat::FatVolume,
};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Write},
    sync::Arc,
};
use virtdisk::RawDisk;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: filesystem-fat-inspect IMAGE [FIRST_CLUSTER SIZE [OUTPUT]]")?;
    let volume = FatVolume::open(Arc::new(RawDisk::open(path)?))?;
    let geometry = volume.geometry();
    println!(
        "family={:?} bytes_per_sector={} cluster_bytes={} cluster_count={} volume_bytes={}",
        geometry.family(),
        geometry.bytes_per_sector(),
        geometry.cluster_bytes(),
        geometry.cluster_count(),
        geometry.volume_bytes()
    );
    if let Some(first) = args.next() {
        let first: u32 = first.parse()?;
        let size: u32 = args.next().ok_or("supply file size")?.parse()?;
        let output = args.next();
        let resources = Resources {
            memory: Budget::new(16 * 1024 * 1024),
            cancellation: Cancellation::default(),
        };
        let file = volume.open_file(first, size, 100_000, &resources)?;
        let mut destination: Box<dyn Write> = match output {
            Some(path) => Box::new(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)?,
            ),
            None => Box::new(io::sink()),
        };
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut done = 0u64;
        while done < file.len() {
            let n = file.read_at(done, &mut buffer, &resources)?;
            if n == 0 {
                return Err("unexpected early EOF".into());
            }
            hash.update(&buffer[..n]);
            destination.write_all(&buffer[..n])?;
            done += n as u64;
        }
        destination.flush()?;
        println!(
            "file_bytes={done} sha256={:x} index_budget_used={}",
            hash.finalize(),
            resources.memory.used()
        );
    }
    Ok(())
}
