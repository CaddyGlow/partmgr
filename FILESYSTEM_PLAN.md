# Filesystem framework and media pipeline implementation plan

## Objective and agreed scope

Build a Rust framework for strict filesystem inspection, file access, new-image
authoring, and recoverable editing. Integrate logical storage from `virtdisk`,
partition management from `partmgr`, and optical/media operations from `mkiso-rs`.

Fast direct file reading and writing inside images and supported disk backends is
a primary requirement, including random access and repeated small operations.
Performance is part of the public API design and acceptance gates, not a later
optimization pass. Access must not require extracting files or rewriting an
entire image for an ordinary supported file operation.

Target families are FAT12/16/32, VFAT, exFAT, NTFS, ext2/3/4, XFS, HFS, HFS+,
HFSX, APFS, JFS, and JFFS2. UDF remains implemented in `mkiso-rs` for now and is
exposed through an adapter. ISO9660 likewise stays with `mkiso-rs`.

DCF is excluded. There are no camera-specific DCIM, naming, numbering, or
media-content constraints.

Read/write support for every listed family is the intended destination. It is
not an initial implementation claim. Track support by on-disk profile and
operation, rather than a single supported/unsupported flag for each family.
Do not promise compatibility with every historical or vendor-specific variant.

This document proposes future work. API and crate names are illustrative.
It does not authorize device erasure, deployment, or publication.

## Current integration boundaries

- `virtdisk` provides logical disk reads, separately opened writable handles,
  container management, and explicit persistence. Container recovery does not
  establish filesystem consistency.
- `partmgr` owns partition inspection, layout editing, table commit/recovery,
  and partition payload boundaries. Its current working tree includes more
  functionality than its older read-only description suggests.
- `mkiso-rs` owns UDF/ISO9660, El Torito, media planning, and device publication.
  Reuse its UDF code; do not create a second UDF implementation.
- The new framework owns filesystem allocation, namespace semantics, file
  metadata, format-specific recovery, and filesystem verification.

Published dependencies must resolve from crates.io. Neighboring checkouts are
useful for integration development but must not be required for released builds.
Record minimum dependency versions when new adapter APIs are required.

## Architecture and dependency direction

```text
virtdisk logical storage
        |
partmgr partition inspection/layout (optional for standalone volumes)
        |
bounded storage region / explicitly supplied auxiliary storage
        |
filesystem discovery -> optional container -> volumes
        |
lossless files, directories, streams, metadata
        |
copy/capture/build orchestration
        |
mkiso-rs optical authoring and media publication
```

Keep filesystem engines independent of partition table types. They receive
bounded storage, not an entire disk and a partition index. A standalone FAT EFI
image can use the same engine without any partition table.

Initially use a small core and format modules. Split into crates where dependency
weight, independent release cadence, or reuse justifies it:

| Component | Responsibility |
| --- | --- |
| `fs-core` | Lossless names, file identities, streams, metadata, budgets, errors |
| `fs-storage` | Read adapters, bounded regions, exclusive sessions, block/flash contracts |
| Format engines | Decoding, validation, allocation, builders, editors, recovery |
| `fsimage` | Discovery, dispatch, capability reports, public facade |
| Integration layer | `partmgr`, `virtdisk`, and `mkiso-rs` adapters; copy planning |

Avoid a dependency cycle: the filesystem core does not depend on `mkiso-rs`.
Place the optical adapter in a higher-level integration component that can
depend on both. Keep partition and container management outside filesystem codecs.

## Required integration refactoring

The initial API review covers the current working trees of `partmgr`,
`../virtdisk`, and `../mkiso-rs`. It is not evidence that these APIs are already
published. The optical package is named `libmkiso` (repository `mkiso-rs`).
Its readers work without default features, authoring requires `native-writer`,
and media orchestration in `boot_media` requires `cli`.

Refactoring these dependencies is in scope. Complete the following contracts
and integration gates before calling the optical work an adapter-only task.
Keep existing public entry points as compatibility wrappers wherever possible.

### R1. Storage-backed UDF reads in `libmkiso`

Current `UdfReader::open` borrows a complete byte slice. Its streaming extraction
API bounds output buffering but cannot read a logical region inside a virtual
disk without first materializing that region. Its allocation extents are private.

- Introduce a portable, fixed-length positional input interface within
  `libmkiso`, with a slice implementation. Keep `virtdisk` bridging in the
  integration layer so portable optical readers do not acquire container or
  filesystem-framework dependencies.
- Refactor discovery, partition translation, allocation decoding, and deferred
  payload reads to use checked bounded reads. Retain the source for all deferred
  access; propagate I/O failures and share resource accounting across that access.
- Expose bounded positional file/stream reads and logical extent visitation,
  including hole semantics. Preserve the existing slice and extraction APIs.
- Adapt ISO's existing `Read + Seek` input using an independent checked cursor
  over a bounded `ReadAt` source. A new ISO input abstraction is not a prerequisite;
  use its existing public extent index for positional payload access.

Acceptance: read UDF and ISO through bounded raw and supported virtual-container
regions, including nonzero region offsets, injected read failures, and large
logical images that cannot be buffered in full. Verify payloads against independent
fixtures and check memory use against declared metadata/scratch budgets.

### R2. File-tree authoring sources in `libmkiso`

Current ISO writers scan host directories. `UdfImage` accepts host file paths or
in-memory payloads; sparse data pieces and named/system streams use owned buffers.
These APIs cannot implement direct filesystem-to-optical capture with bounded
payload memory.

- Define a library-owned source contract for tree inventory, source-scoped object
  identities, metadata, streams, extents, and deferred content reads. Translate
  framework objects in the integration layer; do not make `libmkiso` depend on
  `fs-core` or import its format engines.
- Specify source lifetime/stability, repeated reads, size and identity changes,
  cancellation, and error propagation. Retain hard-link relationships and stream
  ownership through planning. Budget inventories as well as payload buffers.
- Refactor UDF, ISO9660, and bridge authoring to consume this contract. Preserve
  path-based and in-memory APIs as source adapters, and use the same source path
  for boot-image payloads, sparse content, and named/system streams.
- Separate planning/emission from final publication so orchestration can reopen,
  audit, and verify a staged optical image before publishing it. Existing writer
  entry points may retain their documented publication behavior. A generic output
  sink is optional; staging in a host file already satisfies the initial pipeline.

Acceptance: author optical images directly from a filesystem reader without host
tree extraction, including a file and named stream larger than the payload buffer
budget. Exercise deferred-read failures and cancellation before publication, and
validate content, links, and supported sparse/stream semantics independently.

### R3. Optical metadata and preservation profiles in `libmkiso`

Current `UdfEntry` exposes names, kinds, identities, and sizes but lacks the
timestamps, ownership, permissions, and extended metadata required by the common
model. `UdfImage` also lacks corresponding per-entry authoring inputs.

- Add metadata inspection and authoring interfaces for each advertised profile,
  including root metadata, native names, timestamp precision, and opaque fields
  where their meaning is not implemented. Do not assume opaque bytes are safe to
  relocate or transplant into a different filesystem.
- Publish separate read and write preservation matrices for UDF revisions and
  ISO namespaces/extensions. Distinguish absent metadata from metadata the reader
  cannot inspect, and distinguish recognized fields from fields the writer can
  reproduce.
- Have copy preflight compare these matrices with the actual source inventory.
  Reject unsupported preservation requests or require an explicit transformation
  policy before emission. Include special object kinds in this decision.

Acceptance: independently generated metadata fixtures survive supported copies;
unsupported or uninspectable metadata produces explicit preflight outcomes.
Content-only copies must not be reported as faithful filesystem capture.

### R4. `virtdisk` and `partmgr` session adapters

Current `ImageWriter::read_exact_at`, `WriteAt`, and `InspectImage` provide the
initial storage bridge. No mandatory `virtdisk` API refactor was identified.
Implement the owned bounded session in `fs-storage` first, with these constraints:

- Keep the writer private for the session lifetime; do not expose aliases that
  can mutate it outside the session or invoke resize/snapshot management.
- Preserve advisory-lock limitations and the requirement for immutable backing
  parents. Retaining a writer lock is not evidence of protection against arbitrary
  external mutation or mounted-device access.
- Preserve unknown sector geometry as unknown, using explicitly supplied geometry
  when required. Use `InspectImage` facts and per-handle capabilities rather than
  inferring them from the container family.
- Bridge successful `write_all_at` to a full-length `Storage::write_at` result;
  retain partial/uncertain mutation on errors. Preserve flush limitations,
  including publication-directory durability as a separate orchestration step.
- Preserve read provenance and shared budgets through bounded read adapters.
  Keep mutable-session decoders separate from the immutable `ReadAt` contract.

If implementation exposes a missing reusable primitive, propose a narrow additive
`virtdisk` API with a demonstrated adapter use case and failure tests. Do not move
filesystem ownership, journals, or free-space interpretation into `virtdisk`.
Physical-device editing requires a separately specified backend; the raw writer
currently opens regular image files.

Acceptance: exercise the `ImageWriter` -> bounded session -> `partmgr::Storage`
bridge, read-after-write, region crossing/overflow, uncertain writes, flush
failure, and exclusion of management operations. Validate the immutable optical
read bridge separately from mutable editor sessions.

### Refactoring order and release gate

Define R1–R4 contracts during milestone 0. Implement R1 and the R4 storage bridge
before optical source integration; implement R2 and the required R3 preservation
profile before streaming optical authoring. Unsupported metadata can remain
explicitly gated, but cannot silently satisfy a preservation acceptance test.

For each dependency change, record the new public API, compatibility behavior,
owning repository, required feature flags, validation evidence, and minimum
published version. Local integration may use development overrides; released
manifests and lockfiles must resolve without sibling checkouts. Do not assume the
current local package version proves that new APIs exist on crates.io.

## File I/O performance contracts

### Direct access and bounded work

- Expose reusable file/stream handles with positional reads into caller-provided
  buffers, positional writes for supported editor profiles, and explicit batch
  commit/flush. Define EOF, short-operation, cancellation, and uncertain-write
  behavior. Keep convenience whole-file APIs optional and size-bounded.
- Opening a file and reading a small range must not decode its entire payload.
  Support repeated lookup and random access without rescanning a directory tree
  or walking an allocation chain from the beginning on every request. Use bounded
  indexes/checkpoints for chain-based formats and cache validated tree mappings.
- Keep strict local validation on the access path. Separate optional full-volume
  audits from ordinary reads, and report their costs independently. Writers must
  still perform their required ownership audit; reuse its result only within the
  same exclusive session, maintaining it as edits change allocation state.
- Read only the required extents and format-defined compression units. Cache
  decompressed units within a budget; avoid whole-file decompression. Encryption,
  compression, fragmented chains, and container mappings must expose their actual
  amplification rather than claim constant-cost random access for every profile.
- Support in-place range replacement, extension, and truncation where advertised,
  without staging an entire file or rebuilding the image. Recovery may require
  copying affected blocks or retaining old extents; bound this work by the
  transaction/profile and report it explicitly.

### Throughput, concurrency, and cache coherence

- Coalesce adjacent physical ranges after filesystem and container translation;
  use bounded reusable buffers and avoid redundant copies, allocation per block,
  and one host call per sector on sequential paths. Add vectored/batched APIs only
  where measurement demonstrates a benefit, with portable scalar fallbacks.
- Permit concurrent immutable file reads without a shared seek cursor serializing
  unrelated operations. Define file-handle sharing explicitly. Parallelize payload
  reads, checksums, and encoding with bounded queues and backpressure where useful.
- Keep mutation scheduling inside the exclusive editor. Serialize conflicting
  allocation/namespace changes and durability barriers; allow independent payload
  work to overlap only when the format and backend contracts permit it. Do not
  promise concurrent writes merely because a backend trait is `Send + Sync`.
- Budget metadata, directory, extent, container-map, and decompression caches
  together. Key entries by source/session identity and generation. Invalidate or
  update them on writes and recovery; prevent old handles from reading stale
  mappings after deletion, truncation, or allocation reuse. Keep read-after-write
  semantics explicit even when data remains buffered.
- Use bounded read-ahead for sequential access without flooding random workloads.
  Make cache and concurrency limits configurable with conservative defaults.
- Batch allocation changes and contiguous writes within a recoverable transaction.
  Separate write acceptance from durable completion and avoid per-buffer flushes
  unless the recovery protocol requires them. Preserve every required ordering
  barrier; report buffered throughput and durable commit throughput separately.

### Dependency refactoring driven by measurements

R1 and R2 must preserve random access and bounded streaming through every adapter.
For R4, benchmark concrete `virtdisk` backends before treating the current API as
sufficient for performance. Profile seek/mutex serialization, container mapping
lookups, decompression reuse, allocation updates, copies, and host-call counts.
Refactor `virtdisk` or `libmkiso` when these prevent the required access pattern;
candidate changes include native positional host I/O, bounded mapping caches,
batched operations, and narrower lock scope. Maintain portable fallbacks and
existing recovery semantics. Async I/O, direct I/O, and memory mapping are optional
backend optimizations, not requirements of the core file interface.

### Performance acceptance and regression evidence

Establish a benchmark harness during milestone 1 and extend it for each engine.
Measure sequential large-file read/write, random 4 KiB and larger range access,
many small files, repeated lookup, fragmented/sparse files, large directories,
overwrite/append/truncate, and concurrent readers. Include cold and warm cache
conditions with the cache-control method recorded, bounded-memory runs, and
working sets larger than the configured caches.

Measure raw images and representative supported container/chain/compression
profiles separately; add physical-device runs only for an implemented backend.
Record hardware, storage, versions, dataset geometry, cache budgets, concurrency,
wall time, throughput/IOPS, latency percentiles, CPU, peak memory, host I/O counts,
bytes transferred, and write amplification. Include flush/commit latency and
initial validation/audit cost rather than hiding them in setup.

Compare file I/O with equivalent direct logical-region I/O through the same
backend, and with native filesystem tooling where available under comparable
cache, validation, and durability conditions. Set numeric throughput, latency,
memory, and regression thresholds for each supported benchmark profile before
accepting that profile; do not invent one universal MB/s target. Enforce stable
work-count/memory bounds in ordinary tests and timing thresholds on a controlled
benchmark runner. Reject unexplained regressions or document an explicitly
reviewed correctness/performance tradeoff. Revalidate content and recovery after
performance changes.

## Storage contracts

### Immutable reads

Reuse `virtdisk::ReadAt` at the external read boundary. Preserve its fixed-length,
immutable-input contract. An open read-only OS handle alone does not guarantee
snapshot isolation; callers must provide stable storage throughout deferred reads.

Internally share decoders through a minimal positional-read interface usable by
both immutable readers and editor sessions. Do not implement immutable `ReadAt`
on mutable handles simply to satisfy parser signatures.

### Exclusive block sessions

Provide a separately acquired session exposing positional reads/writes, fixed
geometry, flush, and documented exclusivity. A mutable Rust reference does not
exclude external processes; retain the backend lock and enforce the complete
session lifetime contract.

Add a bounded writable region adapter that:

- Uses checked partition-relative byte arithmetic.
- Rejects reads, writes, zeroing, and discard outside the region before mutation.
- Retains its parent session and excludes resize/snapshot management.
- Records logical/physical sector information without assuming filesystem block
  size equals either sector size or container allocation size.
- Does not advertise atomic sector writes without backend evidence.

An adapter can bridge `ImageWriter` and the filesystem session. A second bridge
can serve `partmgr::storage::Storage`; reconcile its mutable/short-write contract
explicitly with `virtdisk::WriteAt` rather than changing either by assumption.

### Flash storage

JFFS2 requires a separate flash model. Define erase/program geometry, erased-byte
value, allowed programming transitions, alignment, and bad-block behavior as
backend capabilities. Model NAND page/OOB layout explicitly when applicable.

Distinguish offline logical JFFS2 images from physical dumps containing OOB/ECC
or bad-block information. Require a declared dump layout; do not guess and then
silently reinterpret bytes. An image backend can emulate erase/program rules
for testing. Actual flash publication requires a dedicated backend and evidence.

### Multiple devices and containers

Discovery returns an optional filesystem container and its volumes. Support
caller-authorized auxiliary devices for profiles with external journals or
separate storage areas. Never search arbitrary host paths for referenced storage.
APFS container editing must own the container session, since space management
can affect multiple volumes.

## Common file and metadata model

Expose lookup, bounded directory iteration, file identities, positional file
reads, stream enumeration, metadata inspection, and logical extent visitation.
Separate generic operations from format-specific extension APIs.

- Preserve native names: byte strings for ext-family and exact UTF-16 where used.
  Display text is an explicit conversion, not the storage representation.
- Let each engine implement comparison, normalization, and collision rules.
  Do not impose host path or Unicode behavior on all formats.
- Represent hard links as multiple directory entries referring to one identity.
- Preserve symlinks without following them by default; expose reparse data separately.
- Distinguish ordinary file data, named streams, and resource forks.
- Represent sparse holes and unwritten extents distinctly from allocated zeros.
- Preserve raw timestamp precision and document conversions and rounding.
- Preserve ownership, modes, ACLs/security descriptors, xattrs, and native flags
  through typed or explicitly opaque metadata with clear interpretation status.

File-tree source/sink adapters should stream content through bounded buffers.
Do not require full extraction into a host directory or entire files in memory.

Copy planning must choose preserve, transform, or reject for each metadata class.
Identify destination name collisions, size limits, and unsupported semantics
before writes. Lossy transformations require an explicit policy and a report.
Never silently discard unknown metadata while claiming faithful capture.

## Capability and validation reports

Each opened volume reports family/version, features, geometry, state, and
operation availability with reasons. Track at least:

- Recognition, validated metadata, complete allocation audit, payload decoding.
- Read, format/build, create, replace, truncate, delete, rename, link, metadata edit.
- Sparse streams, compression, encryption, snapshots/clones, auxiliary devices.
- Recovery support, durability contract, and independent validation evidence.

Unknown incompatible features reject access. Unknown features compatible with
read-only use may permit a documented read profile but must not automatically
permit writes. Define these rules separately for each format.

Separate strict opening from complete auditing: successfully reading one file
does not establish global ownership consistency. Writers require the audit
appropriate to the proposed operation. Dirty, encrypted, or recovery-required
volumes receive explicit outcomes rather than best-effort writable access.

Domain errors retain I/O sources and distinguish invalid data, unsupported
features, exhausted budgets, invalid operations, stale plans, cancellation,
interrupted writes, and uncertain durability.

## Authoring, editing, and recovery

### New filesystem authoring

Inventory inputs, validate semantics, plan allocations, then stream payload and
metadata into an unpublished destination. Make reproducibility an explicit
profile: fixed timestamps/identities, deterministic ordering and allocation,
and controlled initialization of unused bytes.

Check source stability across deferred reads. Fingerprints and size checks alone
are not snapshot isolation; report the actual assurance obtained.

Flush, reopen through the strict reader, audit, and verify file content and
metadata before publication. Cancellation leaves no published output. Document
the backend's publication mechanism and durability limitations.

### Existing-volume editing

Use bounded edit batches under one exclusive session. Preflight source state,
feature support, free space, ownership, and recovery capacity before mutation.
Expose a reviewable semantic plan plus bounded metadata changes; stream payloads.

`partmgr::storage::WritePlan` is a useful execution pattern, but currently rejects
overlapping replacements across stages. Filesystem updates may revisit blocks
and need journal/dirty-state transitions. Do not directly reuse it as a universal
filesystem transaction representation.

Keep transaction protocols format-specific. Share safe I/O, preconditions,
barrier execution, fault injection, and reports. Define the recovery unit and
guarantees for each writable profile before implementing its commit path.

For nonjournaled profiles, select an explicit external undo/redo protocol or
new-output workflow. Recovery storage must not depend on the filesystem being
changed. A container overlay preserves its parent but does not make the child
filesystem transaction crash-consistent.

For journaled profiles, implement the required journal protocol and replay
semantics. Merely setting a clean flag or flushing metadata is insufficient.
Copy-on-write engines need validated allocation, reference accounting, and
publication/checkpoint ordering specific to their format.

Report completed barriers, uncertain writes, recovery identity, and required
next action after failure. Cancellation after mutation begins is a recoverable
interruption, not an implicit rollback. Never retry an ambiguous commit blindly.

## Per-family work

| Family | Reader work | Builder/editor work and gates |
| --- | --- | --- |
| FAT12/16/32 | BPB geometry, FAT entries, chains, ownership, directories, short/LFN names, copies and backup metadata | Deterministic formatting, allocation, file/directory edits, mirrored metadata policy, external recovery |
| exFAT | Boot regions/checksums, allocation bitmap, upcase table, directory sets, contiguous and chained files | Bitmap/FAT consistency, entry checksums, name comparison, dirty-state protocol; TexFAT separately gated |
| NTFS | Record fixups, MFT, attribute lists, runlists, indexes, streams, sparse/compressed data, security and reparse metadata | Stage operations by volume profile; metadata/log recovery and system-file consistency before general editing |
| ext2/3/4 | Superblocks/groups, inodes, indirect maps/extents, directories, xattrs, checksums and feature bits | ext2 first; explicit journal/JBD2 profiles for ext3/4; external journals and advanced features independently gated |
| XFS | Superblocks, allocation groups, inode/directory structures, trees, ownership and feature profiles | Allocation/reference consistency, log recovery, native transaction ordering; advanced features independently gated |
| HFS | Volume structures, allocation bitmap, catalog/extents trees, forks and native naming | Tree maintenance, allocation accounting, metadata/fork preservation and external recovery |
| HFS+/HFSX | Volume headers, catalog/extents/attributes trees, forks, journal and name comparison | Separate case-sensitive profiles, journal-aware editing and native validation |
| APFS | Container discovery, checkpoints, object maps, trees, volumes, extents and feature states | Container-level space/reference management and COW publication; snapshots, encryption and specialized volumes separately gated |
| JFS | Superblocks, inode/directory and allocation structures, log state | Allocation/tree updates and journal replay/commit protocol |
| JFFS2 | Node scanning, CRCs, versions, dirents, compression, reconstruction and erase geometry | Offline image builder first; append/erase/GC and failure recovery for declared flash profiles later |
| UDF | Adapt existing `mkiso-rs` profiles and validation reports | Reuse existing authoring; report existing-image editing separately; keep implementation in `mkiso-rs` |

For FAT, maintain an explicit variant inventory including geometry/name profiles
and transactional extensions. Investigate historical/vendor variants individually
and record specification, fixtures, and read/write status before including them
in any “all variants” claim.

## Pipeline integration

Support these concrete flows:

1. Directory or file-tree source -> FAT EFI image -> El Torito image in `mkiso-rs`.
2. Directory -> partitioned raw image -> independent container conversion.
3. NTFS/ext/other disk volume -> streaming source -> UDF/ISO authoring.
4. UDF/ISO source -> destination filesystem builder -> partitioned disk image.
5. Existing virtual disk -> bounded filesystem editor -> reopen/audit/report.
6. Flash dump -> declared JFFS2 source -> extracted or rebuilt offline image.

Use `partmgr`'s existing filesystem/UEFI integration boundaries where suitable,
without treating an ESP type GUID as filesystem validity or boot success.
Keep table commits, filesystem commits, and boot installation as explicit stages.
A multi-layer orchestration failure needs a stage report and recovery strategy;
do not claim one atomic transaction spanning all layers.

Formatting and filesystem resizing are explicit operations. Container growth
does not grow partitions or filesystems. Define supported grow/shrink sequences
and rollback/recovery constraints before exposing orchestration; leave resizing
unavailable for profiles without validated relocation and boundary checks.

Expose audited free-space ranges for optional discard/compaction. Include all
filesystem metadata, reserved areas, snapshots, and shared allocations in the
ownership model. Discard only under the same exclusive session after the free
space state is durable. Container allocation maps are not filesystem free maps.

## Implementation milestones

### 0. Contracts and specification inventory

Deliver capability schemas, lossless metadata examples, source/sink interfaces,
storage semantics, dependency diagram, and a per-family specification ledger.
Review current APIs in all three repositories before finalizing adapters.
Deliver the R1–R4 refactoring contracts and dependency/API ledger above.

Acceptance: small examples describe read, new build, edit, copy, and failure
outcomes without claiming unimplemented operations. Every family has identified
format references, independent oracles, and feature-profile candidates.

### 1. Storage and shared read foundation

Implement bounded writable regions, exclusive-session adapters, budgets,
structured errors, streaming content, cancellation, and fault-injection backends.
Define reusable positional file handles and build the performance harness and
storage baselines described above before fixing adapter APIs.

Acceptance: boundary overflow and crossing operations fail before mutation;
short writes, I/O failures and barriers have defined outcomes; immutable and
mutable parser entry points preserve their distinct contracts.
Performance workloads have reproducible baselines and explicit resource bounds;
each implemented profile has numeric acceptance thresholds before release.

### 2. FAT and existing optical integration

Implement FAT12/16/32 readers and deterministic builders, VFAT names, exFAT
reader/builder profiles, and UDF/ISO source/sink adapters. Build FAT EFI images
through the same APIs used for disk partitions.
Complete R1–R3 prerequisites for each advertised optical integration profile;
wrapping the current path/buffer APIs alone does not complete this milestone.

Acceptance: independent tools validate all baseline FAT families; file content
and names round-trip; FAT32 EFI images work both as partitions and El Torito
payloads. Firmware success is recorded separately from filesystem validity.

### 3. Reader expansion across the requested scope

Develop NTFS and ext-family first for disk capture, followed by XFS, HFS/HFSX,
APFS, JFS, and JFFS2. Implement each engine's explicit profile, audit, and file-tree
adapter. Specialized features remain reported as unsupported until verified.

Acceptance per family: independently generated fixtures, malformed-input tests,
bounded traversal, native names/metadata preservation, content comparison, and
clear dirty/unsupported-state handling. Do not wait for all readers before
advancing already validated builders/editors.

### 4. Recoverable FAT/exFAT and ext2 editing

Implement external recovery storage and supported create/replace/delete/rename
operations, allocation maintenance, and reopened validation. Add ext2 authoring.

Acceptance: injected failures at writes and barriers have documented recovery
outcomes; no double allocation, unintended data exposure, or silent metadata loss;
native tools accept recovered volumes under the advertised profile.

### 5. Journaled and COW writable engines

Implement ext3/4, XFS, JFS, HFS+, APFS, and NTFS writable profiles independently.
Develop format-specific replay/commit protocols before general namespace edits.
Add HFS editing with its defined recovery mechanism.

Acceptance per operation/profile: independent native validation, journal or
checkpoint interruption tests, allocation/reference audits, content/metadata
preservation, and evidence for the advertised durability guarantee.

### 6. JFFS2 flash mutation and advanced profiles

Add declared flash backends, append/erase behavior, garbage collection and
recovery testing. Expand transactional FAT variants, encrypted/compressed
profiles, external devices, snapshots/clones, and resizing through separate gates.

Acceptance: flash emulation enforces physical rules; hardware-specific behavior
is supported only with corresponding device evidence. Each advanced profile
has its own support matrix and regression corpus.

## Verification and evidence

For each milestone, specify observable behavior, add meaningful independent
fixtures/tests, implement, and run applicable repository checks:

```sh
cargo fmt -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

Run these checks in each changed Rust repository. For `libmkiso` refactors, also
preserve its additional repository gates:

```sh
cargo test --no-default-features --locked
cargo test --no-default-features --features cli --locked
cargo check --no-default-features --target wasm32-unknown-unknown --locked
```

Reader refactoring must retain portable builds, and orchestration must continue
to work with `cli` enabled without `progress`.

Use independent tools where available: FAT/exFAT tools, e2fsprogs, XFS tools,
JFS tools, NTFS tools and Windows-native checks, macOS-native checks for Apple
formats, MTD tools/emulation for JFFS2, and existing UDF/ISO interoperability gates.
Record exact tool versions and commands. Do not treat a repair tool silently
fixing output as successful validation; capture before/after state and diagnostics.

Fuzz malformed inputs, cycles, overlapping allocations, checksums, arithmetic,
names, compression, truncation, and resource budgets. Keep fixture generation
independent of production codecs whenever possible.

Inject short writes, torn writes where modeled, read failures, flush failures,
process interruption, cancellation, stale plans, and failures during recovery.
State the failure model: process-kill tests do not establish actual power-loss
behavior. Recovery should be restartable under its documented contract.

End-to-end tests span raw and supported container profiles, partition sector
sizes, file-tree copies, optical authoring, reopened filesystem audits, and
native access. Test representative combinations plus adapter-specific failure
cases rather than relying on an impractically large undifferentiated matrix.

Host tests do not establish Windows servicing/capture correctness or firmware
boot correctness. Maintain separate native and QEMU/OVMF evidence gates.

## Deliverables and completion criteria

- Versioned public contracts with examples and documented ownership/durability.
- A per-family, per-feature, per-operation support matrix.
- Strict readers and file-tree adapters for all requested families.
- Builders and recoverable editors for explicitly advertised writable profiles.
- UDF integration using `mkiso-rs` without duplicated implementation.
- Independent fixtures, fuzz corpora, native checks, and interruption evidence.
- Direct file I/O benchmarks, per-profile performance thresholds, and regression
  evidence covering both buffered operations and durable commits.
- Pipeline reports separating container, partition, filesystem, copy, and boot outcomes.
- Release dependencies that resolve without sibling checkouts.

The project is complete for an advertised profile only when both successful
operations and failure/recovery behavior pass its evidence gates. Partial family
support must remain visible in capabilities and documentation.

## Reference starting points

- [Microsoft exFAT specification](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification)
- [Linux ext4 structures](https://docs.kernel.org/filesystems/ext4/)
- [Linux JBD2 journal layout](https://www.kernel.org/doc/html/latest/filesystems/ext4/journal.html)
- [Apple File System Reference](https://developer.apple.com/support/apple-file-system/Apple-File-System-Reference.pdf)
- [JFFS2 project documentation](https://sourceware.org/jffs2/)

These are starting points, not a completed specification audit. Add precise
versions, sections, native implementation references, and fixture provenance
for every engine during milestone 0.
