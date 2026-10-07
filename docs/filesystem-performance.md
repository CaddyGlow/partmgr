# Direct access performance evidence

The initial harness is `examples/filesystem-io-bench.rs`:

```sh
cargo run --release --locked --example filesystem-io-bench -- IMAGE 10000
```

Supply a stable, immutable regular raw image. The harness compares identical
sequential and deterministic pseudorandom 4 KiB offsets through the published
`virtdisk::RawDisk` backend and an uncompressed `ExtentFile`. It uses 4096 bytes
of payload scratch, plus an explicitly reported latency sample count. CSV reports
wall time, latency percentiles, logical adapter call counts, bytes and content
checksums. Index validation time is printed separately. These are logical calls,
not measured host syscalls: the backend can amplify or serialize them.

This first baseline deliberately records `cache_control=none`. Backend runs
precede indexed runs and can warm the OS cache; results do not establish a
controlled cold-cache comparison or a release timing gate. Record the command,
image geometry and provenance, toolchain, hardware, storage, memory, filesystem,
and OS version with any saved run. No filesystem reader/editor profile is accepted
on the basis of this harness alone.

Ordinary tests in `tests/fs_file.rs` enforce these work bounds:

- Constructing an indexed 512 GiB logical file performs zero payload reads.
- A 4 KiB read spanning adjacent mapped extents performs one source read.
- Reads inside large sparse holes perform zero source reads.
- Invalid maps, overflow and excessive extent counts fail before source reads.

The map is immutable and source-scoped by ownership of the retained reader.
Constructing it verifies local ranges, not global filesystem allocation ownership.
FAT readers must charge index memory while decoding, and release that reservation
only after the last handle is dropped. ExtentFile's standalone extent-count limit
is not a claim of a shared framework memory budget.

Remaining milestone 1 gates: controlled cold/warm cache runs, container profiles,
concurrency, fragmented maps, lookup and many-small-file workloads, native tool
comparisons, CPU/peak-memory/host-I/O measurements, writes and durable commit
latency, and numeric profile-specific thresholds. Timing thresholds must be set
from reproducible controlled measurements before accepting each implementation.
