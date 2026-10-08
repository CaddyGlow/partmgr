//! Bounded positional FAT/classic ext2/explicit immutable ext reads compared with direct mapped ReadAt calls.
use partmgr::{
    fs_core::{Budget, Cancellation, Reservation, Resources},
    fs_ext::ExtVolume,
    fs_fat::FatVolume,
    fs_file::{ExtentKind, FileExtent},
};
use sha2::{Digest, Sha256};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use virtdisk::{Image, ImageFormat, RawDisk, ReadAt};
const MEMORY_LIMIT: u64 = 256 << 20;
const MAP_LIMIT: usize = 65_536;
type Reader = Box<dyn Fn(u64, &mut [u8]) -> io::Result<usize> + Sync>;
struct Counted {
    source: Box<dyn ReadAt>,
    calls: AtomicU64,
    bytes: AtomicU64,
}
impl ReadAt for Counted {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(out.len() as u64, Ordering::Relaxed);
        self.source.read_exact_at(offset, out)
    }
}
fn copy_extent_map(
    extents: &[FileExtent],
    resources: &Resources,
) -> Result<(Vec<FileExtent>, Reservation), Box<dyn std::error::Error>> {
    if extents.len() > MAP_LIMIT {
        return Err("copied extent-map entry bound exhausted".into());
    }
    let bytes = extents
        .len()
        .checked_mul(std::mem::size_of::<FileExtent>())
        .ok_or("copied extent-map size overflow")?;
    let reservation = resources.memory.reserve(bytes.try_into()?)?;
    let mut copied = Vec::new();
    copied.try_reserve_exact(extents.len())?;
    copied.extend_from_slice(extents);
    Ok((copied, reservation))
}
fn pieces(
    extents: &[FileExtent],
    offset: u64,
    bytes: usize,
) -> io::Result<Vec<(Option<u64>, usize)>> {
    let mut result = Vec::new();
    let mut position = offset;
    let end = offset + bytes as u64;
    let mut index = extents.partition_point(|e| e.offset <= offset) - 1;
    while position < end {
        let e = extents[index];
        let within = position - e.offset;
        let n = (e.length - within).min(end - position) as usize;
        if result.len() == 16 {
            return Err(io::Error::other("request segment bound exhausted"));
        }
        result.push((
            match e.kind {
                ExtentKind::Data(p) => Some(p + within),
                _ => None,
            },
            n,
        ));
        position += n as u64;
        index += 1;
    }
    Ok(result)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !matches!(args.len(), 7 | 9) {
        return Err(
            "usage: filesystem-read-bench FAMILY IMAGE OBJECT LENGTH MODE WORKLOAD OPERATIONS [--backend raw|qcow2|vhdx|vmdk|vdi]"
                .into(),
        );
    }
    let object: u32 = args[2].parse()?;
    let length: u64 = args[3].parse()?;
    let direct = match args[4].as_str() {
        "direct" => true,
        "filesystem" => false,
        _ => return Err("invalid mode".into()),
    };
    let workload = args[5].as_str();
    if !["sequential", "random", "repeated", "concurrent"].contains(&workload) {
        return Err("invalid workload".into());
    }
    let operations: usize = args[6].parse()?;
    if !(1..=65_536).contains(&operations) || length < 4096 {
        return Err("operation or file-size bound invalid".into());
    }
    let workers = if workload == "concurrent" { 4 } else { 1 };
    if !operations.is_multiple_of(workers) {
        return Err("operations must divide by workers".into());
    }
    let resources = Resources {
        memory: Budget::new(MEMORY_LIMIT),
        cancellation: Cancellation::default(),
    };
    let setup = Instant::now();
    let backend_name = if args.len() == 9 {
        if args[7] != "--backend" {
            return Err("expected --backend".into());
        }
        args[8].as_str()
    } else {
        "raw"
    };
    let source: Box<dyn ReadAt> = match backend_name {
        "raw" => Box::new(RawDisk::open(&args[1])?),
        name => {
            let format = match name {
                "qcow2" => ImageFormat::Qcow2,
                "vhdx" => ImageFormat::Vhdx,
                "vmdk" => ImageFormat::Vmdk,
                "vdi" => ImageFormat::Vdi,
                _ => return Err("unsupported backend".into()),
            };
            Box::new(Image::open(&args[1], Some(format))?)
        }
    };
    let backend = Arc::new(Counted {
        source,
        calls: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
    });
    let (read, extents, map_reservation): (Reader, Vec<FileExtent>, Reservation) =
        match args[0].as_str() {
            "fat" => {
                let volume = FatVolume::open(backend.clone())?;
                let file = volume.open_file(object, length.try_into()?, MAP_LIMIT, &resources)?;
                let (extents, reservation) = copy_extent_map(file.extents(), &resources)?;
                let r = resources.clone();
                (
                    Box::new(move |at, out| file.read_at(at, out, &r)),
                    extents,
                    reservation,
                )
            }
            "ext2" | "ext" => {
                let volume = ExtVolume::open(backend.clone(), &resources)?;
                if args[0] == "ext2" && !volume.geometry().is_classic() {
                    return Err(
                        "ext2 benchmark requires classic profile; select ext explicitly".into(),
                    );
                }
                let file = volume.open_file(object, MAP_LIMIT, &resources)?;
                if file.len() != length {
                    return Err("ext length mismatch".into());
                }
                let (extents, reservation) = copy_extent_map(file.extents(), &resources)?;
                let r = resources.clone();
                (
                    Box::new(move |at, out| file.read_at(at, out, &r)),
                    extents,
                    reservation,
                )
            }
            _ => return Err("unsupported family".into()),
        };
    let setup_ns = setup.elapsed().as_nanos();
    let setup_calls = backend.calls.load(Ordering::Relaxed);
    let setup_bytes = backend.bytes.load(Ordering::Relaxed);
    let copied_map_bytes = extents.len() * std::mem::size_of::<FileExtent>();
    let retained = resources.memory.used() - copied_map_bytes as u64;
    if setup_calls > (MAP_LIMIT * 16 + 1024) as u64 {
        return Err("benchmark setup-work gate exhausted".into());
    }
    // Charge duplicate extent map, request descriptors, buffers and latency samples.
    let scratch = resources
        .memory
        .reserve((operations * 96 + workers * 4096) as u64)?;
    let segments = resources
        .memory
        .reserve((operations * 16 * std::mem::size_of::<(Option<u64>, usize)>()) as u64)?;
    let mut requests = Vec::with_capacity(workers);
    let mut expected_calls = 0u64;
    let mut expected_bytes = 0u64;
    for worker in 0..workers {
        let mut seed = 0x4d595df4d0f33173u64 ^ worker as u64;
        let mut list = Vec::with_capacity(operations / workers);
        for i in 0..operations / workers {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let offset = match workload {
                "sequential" => (i as u64 * 4096) % (length - 4096 + 1),
                "repeated" => (length - 4096) / 2,
                _ => seed % (length - 4096 + 1),
            };
            let p = pieces(&extents, offset, 4096)?;
            for (at, n) in &p {
                if at.is_some() {
                    expected_calls += 1;
                    expected_bytes += *n as u64;
                }
            }
            list.push((offset, p));
        }
        requests.push(list);
    }
    // Mapping requests may split at every extent; enforce their explicit bound.
    let request_segments: usize = requests
        .iter()
        .flat_map(|r| r.iter())
        .map(|(_, p)| p.len())
        .sum();
    if request_segments > operations * 16 {
        return Err("benchmark request-segment budget exhausted".into());
    }

    backend.calls.store(0, Ordering::Relaxed);
    backend.bytes.store(0, Ordering::Relaxed);
    let begin = Instant::now();
    let results = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for list in &requests {
            let read = &read;
            let backend = &backend;
            handles.push(scope.spawn(move || -> io::Result<(String, Vec<u128>)> {
                let mut buffer = vec![0; 4096];
                let mut hash = Sha256::new();
                let mut latencies = Vec::with_capacity(list.len());
                for (offset, parts) in list {
                    let started = Instant::now();
                    if direct {
                        let mut done = 0;
                        for (at, n) in parts {
                            let chunk = &mut buffer[done..done + n];
                            if let Some(at) = at {
                                backend.read_exact_at(*at, chunk)?;
                            } else {
                                chunk.fill(0);
                            }
                            done += n;
                        }
                    } else if read(*offset, &mut buffer)? != 4096 {
                        return Err(io::Error::other("short benchmark read"));
                    }
                    latencies.push(started.elapsed().as_nanos());
                    hash.update(&buffer);
                }
                Ok((format!("{:x}", hash.finalize()), latencies))
            }));
        }
        handles
            .into_iter()
            .map(|h| h.join().map_err(|_| io::Error::other("worker panic"))?)
            .collect::<io::Result<Vec<_>>>()
    })?;
    let elapsed = begin.elapsed().as_nanos();
    let calls = backend.calls.load(Ordering::Relaxed);
    let bytes = backend.bytes.load(Ordering::Relaxed);
    if calls != expected_calls || bytes != expected_bytes {
        return Err("payload backend amplification gate failed".into());
    }
    let hashes = results
        .iter()
        .map(|(hash, _)| format!("\"{hash}\""))
        .collect::<Vec<_>>()
        .join(",");
    let mut latency = results.into_iter().flat_map(|(_, v)| v).collect::<Vec<_>>();
    latency.sort_unstable();
    let percentile = |p: usize| latency[(latency.len() - 1) * p / 100];
    println!(
        "{{\"family\":\"{}\",\"mode\":\"{}\",\"backend\":\"{backend_name}\",\"workload\":\"{workload}\",\"operations\":{operations},\"workers\":{workers},\"request_bytes\":4096,\"elapsed_ns\":{elapsed},\"read_latency_p50_ns\":{},\"read_latency_p95_ns\":{},\"read_latency_p99_ns\":{},\"setup_ns\":{setup_ns},\"setup_backend_calls\":{setup_calls},\"setup_backend_bytes\":{setup_bytes},\"payload_backend_calls\":{calls},\"expected_backend_calls\":{expected_calls},\"payload_backend_bytes\":{bytes},\"expected_backend_bytes\":{expected_bytes},\"retained_map_reserved_bytes\":{retained},\"benchmark_reserved_bytes\":{},\"memory_limit_bytes\":{MEMORY_LIMIT},\"map_unit_limit\":{MAP_LIMIT},\"request_segments\":{request_segments},\"worker_sha256\":[{hashes}],\"work_memory_gates\":\"passed\"}}",
        args[0],
        args[4],
        percentile(50),
        percentile(95),
        percentile(99),
        resources.memory.used()
    );
    drop(segments);
    drop(scratch);
    drop(read);
    drop(extents);
    drop(map_reservation);
    if resources.memory.used() != 0 {
        return Err("benchmark reservation refund gate failed".into());
    }
    Ok(())
}
