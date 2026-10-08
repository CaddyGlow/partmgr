# Refactoring benchmarks

Run the hosted release harness against either library configuration:

```sh
cargo bench --bench refactoring --locked -- --samples 10 --warmup 2 --large > std.csv
cargo bench --bench refactoring --no-default-features --locked -- --samples 10 --warmup 2 --large > alloc.csv
```

The executable uses the host standard library for timing even when the library
under test uses only `core` and `alloc`. No benchmark dependency is added.
`--filter SUBSTRING` selects workloads; `--large` adds the maximum 16 MiB GPT
array. The default uses ten measured samples after two warmups.

| Workload | Size field | Logical operation |
| --- | --- | --- |
| GPT sequential/batch rename | Partition entry count | One rename; eight per sample |
| FAT plan | File count | One file planned |
| FAT emit-verify | File count | One output byte; an 8 MiB image per sample |
| APFS open-file | Image bytes | One file opened |
| APFS read-byte | Image bytes | One byte read; 128 per sample |
| APFS owned preparation | Image bytes | One editor prepared |
| NTFS MFT bootstrap | MFT record count | One volume opened |
| NTFS MFT load-parse | MFT record count | One FILE record loaded and parsed |
| NTFS MFT open-stream | MFT record count | One resident/nonresident stream opened |
| USN decode-record V2/V3 | Encoded record bytes | One record decoded; 1024 per sample |
| USN mixed stream | Encoded journal bytes | One record decoded |
| USN load-parse | Encoded journal bytes | One record loaded and decoded |

GPT compares eight sequential edits with one atomic batch and checks identical
arrays and headers before measurement. FAT varies the file count from 1 to 128
to 511, validates emitted payloads independently before timing, and measures
planning separately from emission plus verification. APFS compares strict and
audited handles, and measures fresh owned metadata preparation. Initial APFS
indexing and audit proof creation are outside the open/read measurements.

NTFS uses independently encoded contiguous MFT fixtures with 64, 1024 and 8192
allocated 1 KiB FILE records. Bootstrap measures boot-sector loading, MFT mapping
and volume-information validation; opening a volume does not eagerly parse the
whole MFT. Load-parse explicitly reads every slot, including USA fixups,
attributes and native names. Open-stream parses ordinary file records and opens
alternating resident and nonresident data, including runlist decoding. Tables
are retained across scan samples, while each bootstrap opens a fresh volume.
Payload content and names are checked before timing. These fixtures do not cover
fragmented MFTs, attribute-list extensions or directory-index construction.

USN measures isolated V2/V3 record decoding and alternating-version journals
with 128, 8192 and 65536 records and varied ASCII/Unicode filenames. Setup checks
every field, native reference, name, provenance offset and framing boundary.
Timed decoding borrows names without converting them to strings. Backend counts
are zero for parsing-only cases because journal bytes are already loaded.
Load-parse separately measures buffer allocation, reading the complete encoded
journal through a counted in-memory `ReadAt` backend and parsing it. Journal
extraction from an NTFS `$UsnJrnl:$J` stream, physical disk latency and replay
are outside these measurements.
The additional [NTFS/USN baseline](benchmarks/ntfs-usn-20261008.csv) uses the same
host, sample count and sequential execution as the refactoring baseline.

CSV rows include total measured wall time, batch-derived p50/p95/p99 nanoseconds
per logical operation, backend reads and bytes per operation, and an output
checksum. Each warmup and sample must produce the same checksum. Backend counts
include verification reads for FAT emission. Ten samples provide only coarse
tail estimates; use more samples when investigating variability.

The checked-in [baseline](benchmarks/refactoring-20261008.csv) was collected on
2026-10-08 with Rust 1.99.0 on an Intel Core i7-13700K, using ten samples and two
warmups with `--large`. The two configurations ran sequentially. Storage is
in-memory and counted; caches, CPU frequency and unrelated host activity are
not controlled. Timings describe these fixtures and APIs, not physical disk
throughput. Backend counts are useful for detecting metadata-read regressions.
There are no timing thresholds in CI.
