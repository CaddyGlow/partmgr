# Reproducible FAT and ext2 read measurements

`python3 scripts/filesystem-read-bench.py` builds the release `filesystem-read-bench` example, creates independent native FAT32 and ext2 fixtures, and compares indexed file reads with direct positional reads through the same logical backend. Raw images use `virtdisk::RawDisk`. Add `--containers` to also measure normal and compressed QCOW2 through `virtdisk::Image`; this requires `qemu-img`. A passing receipt establishes content equality and explicit resource/work bounds; timing acceptance on a controlled runner remains unestablished.

The harness requires Linux, Cargo/Rust, dosfstools, mtools and e2fsprogs. Missing tools or Linux `wait4` support produce `skipped` with exit 77. A failed command, numeric gate, content comparison or final image hash check produces `failed` with exit 1. Success produces `passed` with exit zero and retains its `evidence.json`, generated payload/images and complete command logs in a new run directory beneath `/data/cache/partmgr-read-bench-evidence`. Override destinations with `--output` and `--target-dir`, and choose one through ten repetitions with `--repetitions` (default three).

The dataset is a deterministic, independently generated 16 MiB regular file in each 64 MiB raw image. Native FAT32 uses 512-byte clusters. Native ext2 uses `mke2fs -O none -I 128 -b 1024`, then `debugfs` inserts the same payload. Read-only native fsck validates each fixture before measurements. Python identifies the FAT file's root slot and first cluster without production parser code; native `debugfs stat` identifies the ext2 inode. The receipt records these object identifiers, fixture geometry and payload/image hashes. Whole-image hashes must remain unchanged after the measured reads.

Each workload issues 4096 reads of 4096 bytes:

- Sequential reads cover the entire 16 MiB file once. The complete SHA256 must equal the independent payload hash.
- Random reads use a fixed, recorded-in-source linear-congruential seed and bounded byte offsets, including unaligned ranges.
- Repeated reads access the same middle-of-file range using the reusable file handle.
- Concurrent reads use four scoped threads, each with an independent 4 KiB buffer and deterministic random request sequence. The total request count stays 4096.

Every filesystem run is paired with a direct-backend run using the identical fixture and per-worker request sequence. Their worker SHA256 values must match. Each repetition alternates which mode runs first. The harness uses OS-buffered positional reads without dropping caches; it records this uncontrolled cache policy and does not describe the results as cold-cache, controlled warm-cache or physical-media throughput.

Both modes perform the same validated file-index setup. The direct baseline reuses that validated extent map, translates each request into physical `ReadAt` pieces before timing, and then directly reads or zero-fills those pieces. The filesystem mode gives the original logical byte offset to `FatFile` or `ExtFile` on each request. This comparison measures the deferred file-handle path against equivalent physical positional reads on the same backend. The baseline is not an independent allocation decoder and does not include namespace lookup. Index construction is reported separately rather than hidden: setup wall time, backend call count, transferred bytes and retained map reservation are recorded in every run.

The numeric gates for this benchmark profile are explicit:

| Bound | Gate |
| --- | --- |
| Shared filesystem and benchmark reservations | At most 256 MiB |
| Whole benchmark child peak RSS, including startup/setup | At most 256 MiB on Linux |
| Indexed FAT clusters or ext2 logical blocks | At most 65,536 |
| Index-setup backend calls | At most 1,049,600 |
| Requests | At most 65,536 per invocation; harness uses 4096 |
| Physical/zero-fill request pieces | At most sixteen per 4 KiB request |
| Payload backend calls | Exactly the number of mapped data pieces |
| Payload backend bytes | Exactly the sum of mapped data-piece lengths |
| Payload content | Paired worker hashes equal; sequential hash equals source payload |

The request descriptor/segment vectors, duplicate extent map, latency samples and reusable thread buffers are included in shared benchmark reservations before workload execution. The memory cap is a resource gate for this profile, not a claimed universal best memory target. The setup-call bound accommodates the current ext2 allocation validation and provides a finite amplification gate; it is not a promise that setup costs equal raw file reads. No throughput, latency or regression acceptance threshold has been invented for this uncontrolled machine.

Measurements include payload workload wall time, MiB/s, IOPS, per-read p50/p95/p99 latency, workers, request bytes, exact counted backend calls and bytes, index setup wall time/calls/bytes, retained and total reserved memory, plus per-child CPU user/system time, Linux peak RSS, block-input/output counts and context switches obtained through `wait4`. Read latency surrounds only the read operation; workload elapsed time also includes thread startup, content hashing and result collection. Process CPU/RSS/I/O includes setup and execution. Linux `ru_inblock`/`ru_oublock` report 512-byte accounting units, while counted `ReadAt` calls are backend API operations rather than an asserted count of kernel syscalls or physical-device commands.

The receipt also captures machine/platform, CPU information, affinity, memory information and mount information; Python and tool versions/paths/executable hashes; Cargo manifests, Rust sources and script hashes; release binary hash; every exact command and exit status with hashed logs; all individual repetitions and median filesystem/direct elapsed ratios. Source and binary hashes must remain stable through the gate, otherwise it fails and requires a rerun.

This harness currently covers regular-file payload reads on raw-image FAT32 and classic ext2. It does not yet cover namespace lookup, many small files, large directories, independently controlled fragmentation/sparse datasets, larger random ranges, cold-cache control, working sets exceeding all caches, supported container/chain/compression backends, physical devices, writable operations, write amplification, flush/commit latency, or recovery. Those profiles and their numeric timing/regression thresholds must be added before the full plan's performance acceptance can be claimed. Native filesystem tools currently prepare and validate the fixtures; a comparable native file-I/O timing baseline is still outstanding. Timing regression enforcement belongs on a controlled benchmark runner with recorded cache, validation and durability conditions.

Verified receipt: `/data/cache/partmgr-read-bench-evidence/20261007T210524Z-2/evidence.json` passed all 48 runs (two families, four workloads, two modes, three repetitions). FAT retained 3,145,728 map-reserved bytes and reached 5,128,224 total reserved bytes; ext2 retained 2,097,220 map-reserved bytes and reached 4,081,828 total reserved bytes. Maximum measured benchmark-process RSS was 23,784 KiB. Index construction issued 65,537 backend calls for FAT and 179,117 for ext2. These concrete setup counts are part of the evidence rather than payload throughput. All numeric gates, paired content checks, full sequential payload hashes and unchanged image hashes passed. The receipt's per-workload timing ratios remain descriptive measurements on an uncontrolled runner and do not establish performance acceptance.

## Budgeted ext2 metadata indexing cache

The measured 179,117 ext2 setup calls exposed repeated descriptor, bitmap-byte and indirect-pointer reads. `ExtVolume::open_file` now constructs a private, operation-scoped metadata source with at most 64 filesystem blocks and bounded LRU replacement. It reads full metadata blocks once and serves descriptor, allocation-bit and indirect-pointer slices from those blocks while constructing the index. Inode-table metadata uses the same cache. Every existing allocation/range/metadata-alias/cycle check still runs; cached bytes do not substitute for those checks.

The cache reserves its maximum memory through the caller's shared budget before allocation and keeps that lease throughout indexing. At 1 KiB blocks the conservative cache reservation is 72,192 bytes; at 4 KiB blocks it is 268,800 bytes. This temporary requirement can reject an opening operation under a tighter memory budget even when its final coalesced map is small. `open_file` retains the 64-block default. `open_file_with_cache(inode, max_blocks, metadata_cache_blocks, resources)` accepts an explicit cap from zero through 4096 blocks. Zero runs the original uncached indexing path with no cache reservation, so low-memory callers can trade additional backend work for less temporary memory. Positive caps reserve their conservative full capacity before allocation; smaller caps may cause more LRU replacement. The cap is operation-local and does not alter payload mapping or validation. Failed fills are not published as cached entries. Cache leases refund on successful return, failure and cancellation, leaving the existing file-map lease unchanged.

The returned file retains the original uncached bounded source. Its positional payload reads do not populate the metadata cache, acquire its lock or prefetch file content. Cache instances are not shared between opening operations. Source identity and native inode generation remain unchanged, and the immutable-source caller contract still applies; this cache does not create a snapshot or detect transient external mutations.

Independent tests require exactly five metadata-block reads for a handcrafted sparse direct/single-indirect fixture and prohibit payload prefetch. They also exercise failed partial metadata fills followed by successful retry, cancellation, tiny-budget rejection with refunded reservations, unchanged source/generation identity and four concurrent readers whose backend requests remain only the requested four payload bytes. Existing malformed mapping, namespace, native ext2 fixture, tree and whole-volume audit tests continue to pass.

Post-cache verified receipt: `/data/cache/partmgr-read-bench-evidence/20261007T211228Z-2/evidence.json` passed all 48 paired benchmark runs. For the same 16 MiB payload/profile, ext2 setup calls dropped from **179,117 to 80**, and setup bytes from **3,308,105 to 73,984**. Retained map reservations stayed **2,097,220 bytes**. The cache handled more distinct metadata blocks than its 64-block capacity during this fixture, exercising replacement while preserving all content hashes and read-only image hashes. The older receipt remains the before-change evidence; the new receipt records the exact cache implementation tested. Median measured setup wall time changed from roughly 62.9 ms to 6.0 ms on this uncontrolled runner; this observation is not a timing acceptance threshold or a controlled-runner speedup claim.

Configurable-cache equivalence tests exercise caps zero, one, 64 and 4096. The independent sparse fixture requires respectively 18, 14, five and five metadata reads, while producing identical complete payload hashes and source/generation identities. Zero and one succeed under a 4096-byte shared memory budget. The cache lease is refunded before return in every successful case, and a cap above 4096 is rejected before any backend read. The default cache algorithm and cap remain the implementation measured by the post-cache receipt; the configurable wrapper was verified with these focused work-count tests rather than rerunning the unchanged 48-workload default profile.

The fixed native 16 MiB benchmark now enforces metadata indexing work separately
from payload work: FAT setup must use at most 65,537 backend calls and ext2 at
most 256. These fixture-specific limits retain the validated FAT chain walk and
allow bounded ext2 cache replacement, while rejecting the previously measured
179,117-call uncached regression. They are backend-work acceptance gates, not
machine timing thresholds or universal limits for other volume layouts.

Fresh isolated-source receipt
`/data/cache/partmgr-read-bench-index-gate/20261008T001613Z-2/evidence.json`
passed all 16 filesystem/direct runs (four workloads, two families, one repetition).
FAT setup used 65,537 calls; ext2 used 80. All paired payload hashes, memory/RSS,
exact payload I/O and unchanged image/source checks passed. Recorded source hashes
were independently checked against `/data/cache/partmgr-perf-source-bl6oxfxd`.
Controlled-runner timing and durable edit workload thresholds remain open.

The common facade also has a retained FAT12 file concurrency regression in
`tests/fs_image.rs`. Four scoped readers share the same deferred file after the
owning `ReadImage` is dropped. Across 256 deterministic random requests, including
short EOF reads, independent buffers retain exact payload/tail contents and all
workers observe the same identity. Exactly 256 backend reads prove no metadata
rescan for this indexed fixture. Per-request cancellation leaves other requests
usable; owner cancellation remains visible even at EOF. Retained reservations
stay fixed during reads and refund on final drop. This is a work-count and
lifetime contract, not a timing threshold or evidence for other engine profiles.

The japna_nk frozen benchmark checkpoint passed sixteen paired native FAT32/
classic-ext2 runs, with root-audited evidence at
`/data/cache/partmgr-read-profile-bench-japna_nk/20261008T061551Z-2/`.
Copied extent maps now reserve memory before allocation and retain that charge
until the copy is dropped; final memory usage must return to zero. Explicit
`ext` selects the broader immutable reader, while `ext2` rejects nonclassic
geometry. Focused receipt `/data/cache/partmgr-ext-bench-gate-qg6_v69o/receipt.json`
binds the same binary to an independent extent/sparse fixture: direct and
filesystem modes match its complete 4096-byte model hash, and classic mode
rejects it. Neither receipt establishes modern ext native workloads or controlled
timing acceptance.

Extent-enabled file handles now retain a compact separately reserved logical
map after complete extent validation. Maximum-capacity decoder maps, allocation
references and metadata buffers are dropped before returning the handle. Opening
still requires the conservative temporary workspace charge plus the compact map
copy; validation/work ceilings and beyond-EOF allocation checks are unchanged.
This prevents many small retained files from each retaining the full caller map
ceiling. The facade regression retains600 handles under a64MiB pool with a65536
block/map cap: final retained reservations stay below1MiB,600 payload requests
cause exactly600 backend reads, cancellation remains visible at EOF and final
drop refunds everything. This is memory/work-count evidence, not a timing gate.

Frozen CLI receipt `/data/cache/partmgr-modern-ext-copy-78etehpo/receipt.json`
captures the independently authored indexed metadata-checksummed source through
the common facade into classic ext2. Native extraction verifies603 complete
payload/name occurrences (602 unique regular objects), including its actual
alias pair. All334 snapshot files remain hash-identical. This closes a concrete
many-file capture case; broader fragmented/sparse timing workloads remain open.

The container harness uses independently converted normal/compressed QCOW2
images. Before measurements, `qemu-img check`, logical comparison and a complete
raw round trip verify each 64 MiB image. Filesystem and direct modes share the
same selected logical reader. Setup time includes opening the container and
constructing the validated file map. Backend call/byte counters measure logical
`ReadAt` requests; they do not claim to count the container's internal physical
reads. Per-child CPU, RSS and process I/O are recorded separately.

Frozen receipt
`/data/cache/partmgr-container-read-bench-xgu5kd03/20261008T080923Z-2/root-audit.json`
accepts 96 runs: two families, three backend profiles, four workloads, two
repetitions and two modes. Root checked 48 paired worker models, full sequential
payload hashes, four complete converted-image models, exact logical payload
calls/bytes, indexing/memory/RSS limits, unchanged images and 613 artifact hash
bindings. The retained binary and all 322 snapshot files are bound to this
receipt. Required fmt, strict all-target/all-feature locked Clippy and full host
tests pass on that snapshot (439 passed, 38 ignored). Later engine drafts are
outside this checkpoint. Cache state remains uncontrolled; numeric timing,
durable-write workloads and broader profiles remain required.

Shared ext indexed reads now serve the private owned range session directly
through its exclusive storage owner. The retained validated map handles payload
requests without reopening the metadata decoder. The frozen v17 ordinary JBD
tests verify128 repeated/random requests with exactly one payload read each,
and zero backend reads for EOF/empty requests. Native public immutable reader
and private owned range models are independently audited in the indexed-final
and v17 receipts recorded in `filesystem-progress.md`. This establishes bounded
request behavior; it supplies no controlled timing or public owned-editor claim.
