//! Hosted release benchmarks exercising either the std or alloc-only library.
mod support;
use std::{hint::black_box, time::Instant};

struct Options {
    samples: usize,
    warmup: usize,
    filter: Option<String>,
    large: bool,
}
fn options() -> Result<Options, String> {
    let mut options = Options {
        samples: 10,
        warmup: 2,
        filter: None,
        large: false,
    };
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--bench" | "--nocapture" => {}
            "--test" => {
                options.samples = 1;
                options.warmup = 0;
            }
            "--large" => options.large = true,
            "--samples" | "--warmup" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a count"))?
                    .parse::<usize>()
                    .map_err(|_| format!("invalid count for {argument}"))?;
                if value > 1000 || (argument == "--samples" && value == 0) {
                    return Err("samples must be 1..=1000 and warmup 0..=1000".into());
                }
                if argument == "--samples" {
                    options.samples = value;
                } else {
                    options.warmup = value;
                }
            }
            "--filter" => {
                options.filter = Some(arguments.next().ok_or("--filter requires a substring")?)
            }
            "--help" | "-h" => {
                println!(
                    "refactoring [--samples N] [--warmup N] [--filter SUBSTRING] [--large]\n--large includes the maximum 16 MiB GPT array"
                );
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument {argument}")),
        }
    }
    Ok(options)
}
fn percentile(sorted: &[u128], numerator: usize) -> u128 {
    sorted[(sorted.len() * numerator).div_ceil(100).saturating_sub(1)]
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = options()?;
    let mut cases = support::gpt::cases(options.large);
    cases.extend(support::fat::cases());
    cases.extend(support::apfs::cases());
    cases.extend(support::ntfs::cases());
    cases.extend(support::usn::cases());
    if let Some(filter) = &options.filter {
        cases.retain(|case| case.name.contains(filter));
    }
    if cases.is_empty() {
        return Err("filter matched no benchmark cases".into());
    }
    let mode = if cfg!(feature = "std") {
        "std"
    } else {
        "alloc"
    };
    eprintln!(
        "mode={mode}; warmup={}; samples={}; timing=batch_wall_time; setup=excluded; backend=in_memory_counted; cache_control=none",
        options.warmup, options.samples
    );
    println!(
        "mode,workload,size,operations_per_sample,samples,total_ns,p50_ns_per_op,p95_ns_per_op,p99_ns_per_op,backend_reads_per_op,backend_bytes_per_op,checksum"
    );
    for mut case in cases {
        assert!(case.operations > 0);
        let mut checksum = None;
        for _ in 0..options.warmup {
            let metrics = black_box((case.run)());
            if let Some(expected) = checksum {
                assert_eq!(metrics.checksum, expected, "{} output changed", case.name);
            }
            checksum = Some(metrics.checksum);
        }
        let mut timings = Vec::with_capacity(options.samples);
        let mut reads = 0u128;
        let mut bytes = 0u128;
        for _ in 0..options.samples {
            let started = Instant::now();
            let metrics = black_box((case.run)());
            timings.push(started.elapsed().as_nanos());
            if let Some(expected) = checksum {
                assert_eq!(metrics.checksum, expected, "{} output changed", case.name);
            }
            checksum = Some(metrics.checksum);
            reads += u128::from(metrics.backend_reads);
            bytes += u128::from(metrics.backend_bytes);
        }
        let total: u128 = timings.iter().sum();
        timings.sort_unstable();
        let operations = case.operations as f64;
        let measured_operations = operations * options.samples as f64;
        println!(
            "{mode},{},{},{},{},{},{:.2},{:.2},{:.2},{:.9},{:.3},{}",
            case.name,
            case.size,
            case.operations,
            options.samples,
            total,
            percentile(&timings, 50) as f64 / operations,
            percentile(&timings, 95) as f64 / operations,
            percentile(&timings, 99) as f64 / operations,
            reads as f64 / measured_operations,
            bytes as f64 / measured_operations,
            checksum.unwrap()
        );
    }
    Ok(())
}
