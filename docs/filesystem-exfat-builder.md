# Deterministic new-image exFAT builder

`ExfatBuildPlan` directly authors an unpublished clean, single-FAT revision-1.00 image. It does not call mkfs, edit existing images, preserve source metadata or publish output. The caller chooses the sector-aligned byte length, cluster shift, deterministic serial, explicit name profile and `DeterministicDefaults` metadata policy.

Input `ExfatBuildEntry` values retain stable `ObjectId` identities, exact UTF-16 names and parent identities. Direct `Arc<dyn ReadAt>` and indexed `Arc<dyn FileRead>` payloads remain deferred. The caller must stabilize every source through planning, writing and verification; immutable handles alone do not establish a snapshot. Indexed payloads contribute their logical bytes, including defined zero semantics. The builder fully writes these logical bytes; it does not preserve physical sparseness or source allocation.

The only name profile is `ExfatBuildNameProfile::RecommendedTable`. It records the exact recommended compressed table from the [Microsoft exFAT specification, section 7.2.5.1, Table25](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification#7251-recommended-up-case-table): 5836 bytes with TableChecksum `E619D30D` and SHA-256 `8344f27a410a16df14ad98decde32b48c4db0b8e7fa8b9dc4394b58ced972f11`. The functional mapping data is compiled into the module; planning decodes the complete 65536-unit table. Names retain their exact UTF-16 spelling, including unpaired surrogates. Sibling collisions are rejected through this table, rather than host Unicode conversion or locale rules. Siblings sort by up-cased native units, and breadth-first namespace traversal fixes allocation independently of input enumeration or identity values.

The layout contains both boot regions/checksums, one FAT, allocation bitmap, recommended up-case table, root and nested directory entry sets, and directly placed payloads. Bitmap/up-case/root/directories have bounded FAT chains; nonempty regular files use contiguous NoFatChain allocations. Empty files use FirstCluster/DataLength/ValidDataLength zero. Files set ValidDataLength equal to their entire logical payload; directories record their initialized cluster allocation. Namespace entry-set checksums, name hashes and PercentInUse are generated from the final layout. Directory allocations grow to fit their children and retain an end marker; exFAT dot/dotdot entries are not emitted.

Metadata defaults are January 1, 2000 UTC, ordinary directory attributes and archive file attributes. UTC offsets are explicitly valid zero. Source timestamps, ownership, permissions, attributes, stream/link metadata and opaque extensions are transformed or omitted; no preservation claim is made. No volume label or executable boot code is emitted. Unsupported namespace structures are not inferred from regular payloads.

## Bounds and staged verification

Preflight validates geometry and integer ranges, input object/name/depth/slot/heap limits, unique identities, parents, connectivity, native names and total space before any destination mutation. Source payloads are not read or buffered during planning. The explicit shared memory budget covers retained inventory, metadata bytes, temporary full up-case table, canonical keys and traversal indices. Allocation bitmap and FAT contents are rendered into bounded working buffers rather than retaining full-volume arrays.

Emission requires a caller-exclusive pre-sized unpublished `Storage`. Every byte is initialized, including alignment regions, free clusters, unused FAT entries, partial-cluster tails and excess volume tail. Two 64 KiB scratch buffers are separately reserved before writing. Short writes are supported. Cancellation and causal source/output errors are retained. Source/destination length changes fail; attempted writes followed by failure report `InterruptedWrite`, while a failed flush reports `UncertainDurability`.

There is exactly one successful delegated flush. After it, the builder regenerates the entire expected image from metadata and deferred sources and reads back every staged byte. Byte comparison plus whole-image SHA-256 comparison against the emission digest catches output corruption and observable same-length source changes. The resulting report describes staged bytes only. The caller must discard or inspect failed outputs and separately control publication; no firmware boot correctness or physical power-loss recovery follows from these checks.

## Validation

```sh
cargo test --test fs_exfat_builder --all-features --locked
cargo clippy --test fs_exfat_builder --all-features --locked -- -D warnings
```

Portable tests cover nested EFI/BOOT/BOOTX64.EFI payload larger than the working buffer, Unicode/unpaired native names, folded collisions, reversed input ordering, complete reader/audit reopening, zero-initialized free/tail bytes, short writes, explicit preflight limits, stale sources, causal errors, flush/readback failures, same-length content change at flush, indexed FileRead reauthoring, root growth and a multi-cluster up-case table with 512-byte clusters.

The native gate is explicitly ignored during portable tests. Enabling it requires an evidence directory and installed native tools; missing tools fail:

```sh
PARTMGR_EXFAT_BUILDER_EVIDENCE=/data/cache/exfat-builder-evidence \
  cargo test --test fs_exfat_builder --all-features --locked -- --ignored
```

Overrides are `PARTMGR_EXFAT_FSCK`, `PARTMGR_EXFAT_FLS`, `PARTMGR_EXFAT_ICAT` and `PARTMGR_EXFAT_IFIND`; `sha256sum` is also required. Directly authored 32 MiB and 64 MiB images are produced twice with reversed input ordering, compared byte-for-byte and by digest, reopened and completely audited, then checked independently with `fsck.exfat -n`, recursive `fls`, `icat` payload extraction and exact-path `ifind` lookup. Scalar Unicode names are independently preserved; the portable profile separately checks unpaired UTF-16 names.

On 2026-10-08, exfatprogs 1.3.2 and Sleuth Kit 4.14.0 passed the native layout/name/payload gate. Sleuth Kit `ifind` resolved the exact accented spelling but returned `File not found` for its fully up-cased spelling. The receipt explicitly records `native_unicode_upcase_lookup=gap-TSK-ifind-no-full-volume-upcase`; it does not claim independent verification of complete Unicode comparison. The canonical table/checksum, folded collision and checked-reader lookup tests establish the implemented comparison profile. A mounted independent full-table comparison oracle remains acceptance work.

The durable receipt `/data/cache/partmgr-exfat-builder-20261008/exfat-direct-builder-tree-v1.txt` records exact commands, tool versions/executable hashes, source/test hashes, image/payload hashes and retained artifact paths. Current native geometry evidence is 512-byte sectors and 4096-byte clusters. Larger/other-geometry native matrices, preservation profiles, existing-image mutation and firmware gates remain separate work.
