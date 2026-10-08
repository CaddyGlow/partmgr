# virtdisk no_std refactoring plan

This plan applies to the sibling `../virtdisk` checkout inspected on 2026-10-08,
version 0.2.0. It describes coordinated virtdisk and partmgr work. No source
changes are included in this plan.

## Goal and API design

Provide a stable Rust `no_std` + `alloc` library for bounded virtual-disk parsing
and positional reads from caller-supplied storage. Host capabilities remain
available by default. Breaking API changes are explicitly allowed; legacy APIs,
compatibility shims and unchanged downstream implementations are not requirements.
Preserve data correctness, resource bounds and host recovery guarantees.
Allocation-free operation is a separate project:
format indexes, parent graphs, decompression buffers and retained proofs currently
need heap storage.

Introduce `default = ["std"]`; make `cli` enable `std`. Add
`#![cfg_attr(not(feature = "std"), no_std)]` and `extern crate alloc`. Host files,
path resolution, locks, transaction journals and process integration require
`std`. Make their dependencies optional and activate them through that feature.
Do not pretend an unsupported host operation succeeded in a no_std build.

Replace the existing `ReadAt` with one portable trait using portable result,
context and budget types in both feature configurations. Migrate format readers,
constructors and callers directly to this API. Apply the same design to every
public policy boundary: `ParserLimits::validate`, `ReadBudget` construction and
charging methods, `ReadBudget::reader`, `ReadContext`, `ReadError`, and view and
extent APIs. Host file readers implement the portable trait and convert OS errors
at their boundary; there is no parallel legacy reader trait or constructor family.

The portable module, trait signatures, error types and policy APIs must exist
unchanged with and without `std`, including when Cargo feature unification enables
`std` transitively. Host-specific path and filesystem identity data belong in host
adapters, not feature-dependent fields or signatures of portable types. Document
the API migration and use an appropriately breaking release version.

## Portable storage and errors

Extract `ReadAt`, `DiskExtent`, `ExtentKind`, checked-range operations and
`DiskView` mechanics from `src/lib.rs` into a portable module. The portable trait
must retain fixed-length, exact positional reads, overflow rejection, sparse
extent semantics, budget propagation and deferred-read provenance. In particular,
an empty read at EOF succeeds and an empty read beyond EOF fails. Reader errors
may leave part of the output modified; callers must still discard it.

Define dependency-independent portable errors with concrete kinds for bounds,
invalid metadata, unsupported profiles, resource limits, cancellation, allocation
failure and backend failure. Preserve machine-readable budget/context details.
Use `core::fmt` and `core::error::Error`; do not stringify typed errors at adapters.
The host adapter must retain the original `std::io::Error` and OS error code as
its source when converting host failures, with typed access to the original
error and OS code. Define and test mappings into portable error kinds. Avoid
depending on ruzstd's internal I/O error type for the public storage boundary.

Separate format provenance from host `PathBuf`: portable context can retain
partition numbers, UTF-16 stream/components, record identifiers and offsets;
host adapters retain native paths and filesystem identities. A portable diagnostic
label is not proof that two sources identify the same file.

Define a portable `SourceIdentity` token for every source participating in a
parent graph or multi-source descriptor image. Tokens identify retained container
storage, including the region for an embedded container; equal bytes, format UUIDs/CIDs, labels and `Arc`
addresses are not storage identity. The trusted storage provider or graph
registry must issue tokens consistently: aliases and transparent wrappers over
the same container retain one token, while distinct containers receive distinct
tokens. Document token namespaces and lifetime so independent providers cannot
accidentally collide. Host adapters derive or register tokens from retained
filesystem identities and continue checking path replacement separately.

Supplied parent handles are explicit authority, never authority inferred from a
locator string. Portable graph construction validates native parent linkage,
rejects a token repeated along an ancestor path, and retains the current depth
limits. Shared ancestors in separate branches remain valid. If reliable identity
is unavailable, refuse parent-graph and multi-source descriptor construction
with a typed error; standalone single-source reads remain available. This is a
trusted-provider contract, not proof against a provider that lies about identity. Test two wrappers over one source, distinct
sources with identical contents, token namespace collisions, repeated ancestors,
shared ancestors, linkage mismatch and missing identity.

Port `policy.rs` and pure parts of `physical_validation.rs` first. Keep all
hard ceilings, checked arithmetic, cache reservations and cumulative charges.
Use fallible reservations where the current bounded contract requires them.
File metadata fingerprints and capture checks stay host-only; hashing supplied
immutable bytes can be portable.

## Ownership, synchronization and format readers

Move `Vec`, `String`, `Box`, `Arc` and ordered collections to `alloc`, and numeric,
formatting and iteration imports to `core`. Do not replace `Mutex` with `RefCell`
behind a reader still promising `Send + Sync`. Separate source-independent parsed
indexes from host synchronization. Prefer immutable indexes and caller-owned
scratch/cache state; for shared QCOW2 caches use an explicit synchronization
backend or documented optional lock feature. Keep a safe uncached portable mode
as the initial implementation, preserving output validation and enforcing
explicit accounting rules for that mode.

Define cached and uncached accounting explicitly. Cache implementations and exact
charge counts may change, provided bounds remain enforced and reservation release
is correct. Document changes to refusal behavior. For uncached accounting: charge every actual
source read and format work item, charge metadata materialization before reading,
and reserve all live scratch/decompression storage before allocation. Release
scratch reservations when the operation ends; do not charge retained cache bytes
for entries that are never retained. Repeated lookups therefore can consume more
work or cumulative metadata than a cached lookup. Never reset cumulative counters
or skip validation to imitate cache hits. Retain format, depth, arithmetic and
decompression ceilings; distinguish bounds required by the format from bounds
that exist only to limit a retained cache.

Document each mode's expected charge and refusal behavior. Compare logical
output and corruption rejection across modes, but assert budget usage and
resource-limit errors against the documented mode rather than requiring identical
counters. Add repeated-read, tight-budget, failed-charge and reservation-release
tests for both host cached reads and portable uncached reads.

Inventory every `HashMap` and `HashSet`, including QCOW2 mapping entries, snapshot
ID duplicate detection and refcount-block ownership validation. Portable indexes
and validation sets need an explicit choice per use: use
`alloc::collections::BTreeMap`/`BTreeSet` where the allocation contract permits
infallible node allocation, or fallibly reserved ordered `Vec` storage where a
typed allocation failure is required. Stable B-tree insertion does not provide
`try_reserve`; do not promise recoverable allocation failure around it. The host
hash cache may remain or be replaced by a reviewed bounded implementation. Charge key storage,
node/capacity overhead and traversal work conservatively before insertion, retain
applicable entry-count limits, and account for ordered-vector insertion/sorting
work. Verify long/duplicate IDs, large ownership sets, fallible-reservation errors
and tightened metadata/work limits. If a measured need instead justifies
`hashbrown`, review its alloc-only features, fallible capacity reservation, hasher
and adversarial collision bounds explicitly rather than enabling defaults. Record
the collection and allocation strategy for every inventoried use before porting.

`alloc::sync::Arc` and the existing `AtomicU64` accounting in `policy.rs` restrict
which bare-metal targets work. Initially document pointer-atomic and 64-bit-atomic
requirements, and validate on `x86_64-unknown-none`. Supporting targets without
these atomics requires a separate single-owner API or a reviewed critical-section
backend; avoid promising all embedded targets merely because one target builds.

Port raw in-memory views, VDI and uncompressed QCOW2 first; then compressed QCOW2,
VMDK descriptors/sparse mappings and VHDX headers, mappings and recovery overlays.
Format readers consume caller-supplied parent and extent handles and native
locator records. Move `open_chain`, canonicalization, symlink checks,
authorized-path lists and filesystem resolution into host adapters. Keep identity/linkage checks,
cycle detection and chain-depth limits in the portable validation layer.

For descriptor-based VMDKs, define an explicit binding from each parsed extent
entry to a retained caller-supplied source handle and `SourceIdentity`. Descriptor
names identify requested bindings; they grant no authority to open storage. Keep
path lookup and authorization in host adapters. Validate complete, unambiguous
bindings, extent kind, checked offsets and lengths, sparse capacity, and descriptor
profile before exposing reads. Retain one shared budget across the descriptor,
extents and parents, including deferred reads.

Preserve VMDK's rejection of repeated extent sources and extents aliasing the
descriptor, another extent or an already opened ancestor dependency; ancestor-path
cycle checks alone do not enforce this rule. Perform these checks for standalone
descriptors too. Define the token registry's underlying-storage identity separately
from embedded-container region identity where needed to preserve host file-alias
rules; taking a different view of a file must not bypass those rules. Add portable
flat and sparse split-image fixtures, with and without parents, and cases for
missing/duplicate bindings, two wrappers over one extent, descriptor/ancestor
aliases, distinct sources with identical bytes, invalid offsets, capacity mismatch,
missing identity and shared-budget exhaustion. Shared graph ancestors remain valid
where they do not violate these format-specific extent restrictions.

QCOW2 `open_with_limits` currently consults a filesystem journal when the source
context carries a path. Extract this host recovery check explicitly before invoking
the pure parser; moving it behind a feature must not weaken the default host
recovery policy. Likewise preserve VHDX recovery validation and parent linkage.

`ExtentFile` is defined in partmgr's `src/fs_file.rs`, not in virtdisk. After the
portable reader API is published, port this immutable extent map using `alloc`
and the portable trait. Its stricter beyond-EOF behavior is distinct from the
filesystem `FileRead` contract and must remain unchanged. Filesystem caches,
source stability checks and owned metadata discovery need their own partmgr
portable implementations. The requested partmgr deliverable includes all
filesystem engines with alloc; gating those engines out is not an acceptable
completion criterion. Only host-specific adapters should be unavailable without
std. Scoped metadata decoder threads need a thread-free implementation retaining
exclusive storage ownership, cancellation, accounting and decoder correctness.

## Dependency decisions

These observations are from locally cached manifests and source, not inferred
from package names:

| Dependency | Current use | Portable treatment |
| --- | --- | --- |
| `sha2` 0.10.9 | SHA-256 and fingerprints | Set `default-features = false`; its default `std` feature enables `digest/std`. Enable that feature from virtdisk's `std` feature if needed. Validate each supported target/backend. |
| `flate2` 1.1.10 | Raw DEFLATE QCOW2 clusters | Despite `#![no_std]`, stable builds still execute `extern crate std`; `rust_backend` does not remove this requirement. Its custom `flate2_unstable_nightly_alloc_io` cfg is not a stable portability solution. Replace the portable cluster path with bounded direct `miniz_oxide` decoding or another verified alloc decoder. Use the verified decoder for both host and portable reads; remove the production flate2 dependency after malformed-input and output equivalence tests pass. It may remain a dev-only fixture generator. |
| `ms-compress-ruzstd` 0.9.1, aliased `ruzstd` | Zstd QCOW2 clusters | Already has an alloc no_std implementation. Use `default-features = false, features = ["hash"]` to keep checksum validation, and enable `ruzstd/std` only from the host feature. Bridge `io_nostd` or use the frame decoder directly; existing `std::io::Read` calls cannot carry over unchanged. |
| `same-file` | Host alias/identity checks | Optional, `std` only; do not replace physical identity with string comparison. |
| `getrandom` 0.3 | New VDI/VHDX UUIDs in `native_id.rs` | Optional host dependency. Future portable creators accept caller-supplied validated UUIDs or an explicit entropy provider; never substitute deterministic randomness. |
| `rustix` 1.1.5 on Linux | File opens/locks and filesystem operations | Optional, Linux plus `std`. A no_std Linux target must not accidentally activate it solely through `target_os`. |
| `tempfile` | Tests | Dev-only host fixture helper. |

For direct DEFLATE decoding, preserve exact cluster-sized output, raw DEFLATE
semantics, decoder completion, bounded input/scratch/output, truncation rejection
and the existing policy for trailing input. For zstd preserve maximum window,
declared content-size checks, exact output length and checksum verification.
Test malformed and expansion-heavy inputs; successful round trips alone are
insufficient.

## Host and writable boundaries

Keep `RawDisk`, `source.rs` file wrappers, path-backed image graphs and manifests,
`reader_open.rs` host options, `native_id.rs`, CLI and filesystem export/import
adapters behind `std`. `RawDisk` currently serializes seek/read through a mutex;
preserve cursor safety when reorganizing it or use platform positional I/O with
the same exact-read contract.

Initially gate existing writable profiles, `image_writer.rs`, `writer_open.rs`,
`transaction*.rs`, sidecars, graph replacement, compact operations and file-backed
journals together. Durable flush order, rename/replace behavior, file locks,
directory sync and recovery evidence are host capabilities, not generic byte
writes. Later extract pure mutation plans and a portable write/flush interface
only with explicit durability guarantees supplied by the caller. Preserve error
classification and recovery-required behavior on the host path throughout.

## Implementation sequence and exit gates

1. Add the feature/module skeleton, optional dependency wiring and compile-gated
   host targets. Establish the unified portable reader, error and policy APIs
   with contract tests; adapt host I/O at the OS boundary.
   Verify a real bare-metal target immediately before migrating formats.
2. Move bounds, views, context and budgets; add in-memory test backends. Test
   overflowing/empty ranges, source errors, cancellation and reservation release.
   Migrate callers to the new APIs and test policy methods, typed errors and
   context propagation in both feature configurations.
3. Separate parsed metadata from OS discovery and caching; port raw/VDI/QCOW2
   reads and allocation traversal. Compare portable and host logical output,
   corruption rejection and structural ceilings on existing corruption fixtures.
   Specify and test the separate cached/uncached accounting contracts, including
   repeated lookups, collection insertion bounds and reservation release.
4. Port bounded DEFLATE/zstd and then VMDK/VHDX portable readers. Exercise supplied
   parent chains, malformed locators, alias tokens, token namespaces, cycles,
   shared ancestors, missing identity, linkage mismatch and recovery views. Port
   descriptor extent bindings and test standalone and parented flat/sparse split
   VMDKs, repeated/aliased extents, capacity checks and shared accounting.
5. Reorganize host writable/graph/CLI code around the portable layer. Run existing
   recovery-cut and adversarial-identity suites; avoid widening host trust rules.
6. Validate migrated downstream callers using temporary local patches, then
   publish a breaking crates.io release with portable APIs and migration notes.
   Update partmgr's migrated filesystem readers/extent handles and owned editor
   discovery to use the published version with disabled defaults and explicit
   feature wiring.
   Published builds must never require the sibling checkout. Temporary local
   patches may be used for joint development but must not enter release manifests.

Required validation for virtdisk after each integrated phase:

```sh
cargo fmt -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo clippy --lib --tests --no-default-features --locked -- -D warnings
cargo test --lib --tests --no-default-features --locked
cargo check --lib --no-default-features --locked
cargo check --lib --no-default-features --locked --target x86_64-unknown-none
cargo tree --no-default-features --target x86_64-unknown-none -e features
```

The selected Rust toolchain must include that target's core/alloc libraries.
Inspect the complete dependency tree for accidental `std` activation. Add a tiny
independent no_std consumer that implements the portable reader and parses an
in-memory fixture; compiling the library alone does not prove API usability.
Tests may run under the host test harness while importing portable APIs, but a
successful host `--no-default-features` check alone is not evidence of no_std
support. Compile-gate host-only tests while keeping portable contract, corruption,
compression and accounting tests runnable without the crate's `std` feature.
The `--tests` gate must execute portable integration fixtures under `tests/`,
not only unit tests under `src/`. Split mixed host/portable test modules and adapt
in-memory backends to the unified trait. Reuse or extract existing corruption
fixtures, replacing dependencies on host-only image creators with prebuilt or
portable byte fixtures where necessary. Track coverage for each migrated format,
compression decoder, parent chain, split VMDK, VHDX recovery overlay and accounting
mode. Compile-gating an entire suite out does not satisfy that coverage requirement.
Run these fixtures both without defaults and with all features; add each format's
portable integration coverage in the phase that ports it.
Do not treat dev-dependency feature activation as bare-metal validation.

Keep the independent consumer's portable trait implementation and constructor
calls identical in two host build configurations: one disables virtdisk defaults;
the other enables virtdisk `std` through a second dependency in the same Cargo
graph. This explicitly tests feature unification rather than only testing two
separate library builds. Both configurations must compile the same portable API,
retain typed errors/context, and exercise the same fixture expectations. Include
`ParserLimits::validate`, `ReadBudget` creation/charging and reader wrapping,
`ReadContext`, views and extent traversal in this consumer. Host adapter tests
separately verify OS error retention, identity and recovery checks.
The bare-metal consumer disables defaults and must not pull in the host-enabling
dependency. Compile it for `x86_64-unknown-none` and inspect its complete feature
tree. Add that target to the pinned Nix toolchain's target list; installing it only
in an unrelated rustup toolchain does not satisfy this gate. Run
packaging/published-dependency checks without sibling patches.

Partmgr's current deliverable retains all filesystem engines and alloc-backed
partition parsing/editing without std, using a local portable I/O
boundary until virtdisk publishes its portable interfaces. Adapt that boundary to
the published upstream types in phase 6 without changing filesystem semantics.
Filesystem adapters that operate on caller storage remain portable; file-backed
and ImageWriter-backed adapters stay host-only. Explicitly test the thread-free
owned decoder path against the host scoped decoder and its resource limits.
Host tests also do not establish firmware boot,
Windows servicing or capture correctness; retain the existing separate native
validation gates.
