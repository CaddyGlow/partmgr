# Optical positional reader integration

`integration/optical` is a standalone, unpublished consumer package using the
registry version declarations `partmgr = "0.1.0"` and `libmkiso = "0.1.4"`. Its
portable default disables libmkiso native writers. The root crate does not
acquire an optical dependency or require a sibling checkout. Development
`Cargo.lock` and target artifacts are ignored; no sibling paths or patches are
stored in the manifest. Initial development used local libmkiso 0.1.2/0.1.3;
published crates.io libmkiso 0.1.4 now passes the integration suite, strict Clippy
on native hosts. Its earlier no-default-feature wasm build passed with
virtdisk 0.1.0; after migration to published virtdisk 0.2.0 the plain wasm gate
fails on getrandom. A flags-only diagnostic is not a portable release check. The tested registry checksum is
`dd33c7015ccbe611f686f84f27aa6baa8d075eed8ed26edde55460f72eee54d9`.
The minimum published partmgr version containing the new filesystem contracts
also remains unverified; the local 0.1.0 package version is not release evidence.

`SourceAdapter` retains an `Arc<dyn virtdisk::ReadAt>`, its fixed observed length,
the caller's shared `Resources`, and a cumulative requested-byte budget. Both
metadata discovery and every deferred file handle use this same adapter.
Bounded-region/provenance/read-context wrappers supplied by the caller remain
on the actual backing read path. The adapter checks cancellation, length
stability, ranges, read accounting and transient shared scratch reservations;
it preserves backing I/O failures as causal errors. It does not establish a
snapshot: the caller must guarantee unchanged source bytes and length throughout
all deferred access. Source-scope and generation are supplied explicitly.

`OpticalReadIndex::iso` discovers one explicit primary, Joliet or Rock Ridge
namespace through an independent checked `SourceCursor`; file sections become
validated `ExtentFile` maps. No host pathname or lossy display path drives file
reads. Raw namespace identifier bytes and native inspected metadata are retained;
ISO identities identify indexed records within the supplied source/generation.
These identities do not claim cross-namespace hard-link recognition.

`OpticalReadIndex::udf` discovers through the retained positional source, copies
validated recorded/zero extent maps, and releases the parser after inventory.
The upstream parser uses single-threaded bookkeeping and is never unsafely made
`Send` or `Sync`. The resulting deferred `FileRead` handles use the immutable
source and `ExtentFile`, with no parser cursor or whole-file payload allocation.
UDF identities retain partition/ICB keys, so hard-linked names share identities.
Raw OSTA identifier bytes, owner-associated named/system stream information,
inspected native metadata, and unfollowed symbolic-link targets are retained.
`open_file` rejects directories and symbolic links rather than returning empty
files. Metadata retains upstream `Absent`, `Uninspected`, `Present` and
`NotWritable` states; output preservation is a separate policy decision.

Discovery reserves a conservative inventory envelope before parsing: four times
the selected metadata limit, 1024 bytes per permitted entry, and 128 bytes per
permitted extent. It applies upstream entry, metadata and depth limits and a
cumulative retained file-section limit. The reservation remains alive across
index removal until its last deferred file handle is dropped. Both discovery
and payload scratch share the supplied source `Resources`; callers should use
that same pool for index planning and all cooperating readers.

Published libmkiso 0.1.4 provides `visit_classified_extents`. The adapter retains
recorded data, unallocated holes and allocated-unrecorded extents as distinct
`Data`, `Hole` and `Unwritten` classes. Zero classes read as logical zeros without
reading their backing payload. Common `FileRead::visit_extents` now exposes these
validated classes instead of rejecting sparse UDF files. The compatibility
upstream unclassified visitor is not used to infer allocation semantics.

Focused tests generate actual images with libmkiso's native writers: an ISO
nested multi-cluster file and a UDF 2.01 Japanese-name sparse file, allocated
unrecorded body, hard link, named stream and symbolic link. Sources embed each
image at a nonzero physical offset behind a bounded positional wrapper. Tests
cover repeated deferred reads, exact native UDF bytes, zero/data boundaries,
stream ownership, identity retention, distinct sparse/unwritten extent visitation, causal payload failure, cancellation, and shared memory/read budgets.
These initial three fixtures establish host behavior. The additional R1 gate
below adds independent native extraction and QCOW2 container evidence; neither
gate establishes firmware correctness.

Development verification needs only the new partmgr API checkout override:

```sh
cargo test --manifest-path integration/optical/Cargo.toml --test read \
  --config 'patch.crates-io.partmgr.path="/path/to/partmgr"' \
  --target-dir /data/cache/partmgr-optical-read-target
```

Five ordinary reader tests and the explicitly enabled native R1 gate pass against
published libmkiso 0.1.4 and virtdisk 0.2.0, together with all-feature Clippy.
The plain portable wasm gate remains open as described above.
The new partmgr API release still needs verification without its override.

## R1 container and independent extraction gate

`r1_iso_udf_normal_and_compressed_qcow2_large_logical_source_gate` adds the
`optical-container-r1-v1` profile. It generates ISO and UDF optical images with
a 131,089-byte deterministic payload, streams each image behind an 8192-byte
raw prefix and before a suffix, and converts that raw wrapper into normal and
compressed (`-c`) QCOW2 through `qemu-img`. Each QCOW2 is resized to an 8 GiB
logical disk and checked independently with `qemu-img check`.

The production read path is `RawDisk -> Qcow2::open_with_limits -> DiskView`
restricted to the exact optical image at offset 8192, followed by `SourceAdapter`
and the selected optical index. Each case checks 69 beginning, boundary, EOF
and deterministic random payload ranges against independently generated expected
bytes. Compressed cases must actually increment the container's decoded-byte
counter; normal cases must leave it zero. This checks actual QCOW2 decoding,
not just a filename or compression option.

Filesystem metadata and scratch share an 8 MiB `Resources` pool. Container
parsing separately retains caller-tightened shared limits: 8 MiB metadata,
2 MiB cache, 64 KiB compression-unit buffer, and 64 MiB cumulative decoded
output. Source discovery and deferred payload access also share a 16 MiB
requested-byte ceiling. The 8 GiB source cannot be buffered under these bounds.
The retained filesystem charge in the verified cases is 1,146,880 bytes; the
container cache is released when the last handle and source adapter are dropped.

The explicitly enabled native gate requires qemu-img, sha256sum and 7z/7zz.
The latter independently extracts the original optical ISO and
UDF fixtures and its payloads must match expected bytes exactly before container
checks proceed. Missing tools or failures are fatal when enabled; the native
test is ignored by default. The verified environment ran both native
oracles successfully. p7zip emits a UDF tail-data warning for the retained backup
anchor region; its extraction exits zero and the exact payload comparison passes.

The separate query-forwarding test verifies that SourceAdapter preserves exact
container/partition/native-path provenance (including unpaired UTF-16 units),
returns the same shared container budget, and forwards sparse-hole queries.
Queries are not replaced with default context or independent counters.

Set `PARTMGR_OPTICAL_READ_EVIDENCE` to a writable evidence directory to retain
all generated optical/raw/QCOW2 images, native extracted files and the command
receipt `optical-container-r1-v1.txt`. The receipt records exact tool commands,
stdout/stderr, exit status, library version, limits, observed counters and range
comparisons. Without this variable fixtures are temporary. Example invocation:

```sh
PARTMGR_OPTICAL_READ_EVIDENCE=/data/cache/partmgr-optical-read-r1 \
  cargo test --manifest-path integration/optical/Cargo.toml --test read \
  --config 'patch.crates-io.partmgr.path="/path/to/partmgr"' \
  r1_iso_udf -- --ignored --nocapture
```

The verified registry-libmkiso run used qemu-img 10.2.4 and p7zip 17.05, with
only the new partmgr API checkout override. Its receipt is
`/data/cache/partmgr-optical-read-registry-20261007/optical-container-r1-v1.txt`.
All four ISO/UDF normal/compressed profiles pass. This establishes the selected
container and content profiles; it does not establish firmware correctness,
faithful optical metadata rewriting, or publication of the new partmgr APIs.

The selected native namespace can now be consumed through [`OpticalTreeSource`](filesystem-optical-tree.md), using published 0.1.4 parent/root/semantic-leaf APIs instead of display-path reconstruction. Published 0.1.4 native R1 container evidence is retained at `/data/cache/partmgr-optical-read-registry-v014-20261007`; native ext2 capture evidence is retained separately at `/data/cache/partmgr-ext-optical-registry-v014-20261007`. These receipts do not establish firmware boot or faithful destination metadata emission.
