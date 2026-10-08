# Immutable exFAT volume reader

`fs_exfat_volume` opens an immutable positional source after `ExfatBoot` validates its boot regions. Callers supply explicit `ExfatReadLimits` and shared `Resources`. The supported profile is revision 1.00, one FAT, a clean volume, standard allocation bitmap/up-case/label entries and standard file entry sets. TexFAT, dirty/media-failure state, unknown flags and unsupported directory extensions fail explicitly.

The reader implements the allocation and namespace rules in the [Microsoft exFAT specification](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification): bounded FAT chains, contiguous NoFatChain streams, bitmap allocation checks, up-case checksums and complete compressed or uncompressed tables, entry-set checksums, native UTF-16 names and up-case name hashes. Exact native units survive indexing, including unpaired surrogates; lookup uses the actual validated volume table. Root, bitmap and up-case allocation must be disjoint; files and directories cannot alias these protected system clusters.

`root_directory` and `read_directory` return retained, budgeted inventories. `allocation_clusters` exposes the directory allocation for callers performing whole-tree overlap audits. Entries carry volume-scoped identities based on their physical directory slot. `raw_metadata` preserves the full standard entry set; this module does not interpret timestamps. A foreign entry is rejected.

`open_file` creates an indexed `FileRead` with direct positional payload access. Recorded initialized bytes appear as `LogicalExtent::Data`; the allocated tail beyond ValidDataLength appears as `Unwritten` and reads as zero without reading its backing bytes. Handles and clones retain the shared source and reservations after the volume is dropped. Known-size stream maps and directory inventories reserve memory for their actual bounded sizes, including temporary map copies and a fixed empty-object charge. The unknown-length root FAT traversal reserves its configured chain cap. A low-memory regression retains multiple tiny objects with large configured caps. Metadata indexing never buffers the full volume or file payload. Cancellation, memory limits, source-length changes and causal backing I/O errors are checked. The caller must keep the source immutable: length checks do not establish a snapshot.

## Validation

Run portable checks with:

```sh
cargo test --test fs_exfat_volume --all-features --locked
cargo clippy --test fs_exfat_volume --all-features --locked -- -D warnings
```

Six tests exercise an independently encoded 2 MiB image: contiguous and fragmented files, nested directories, exact UTF-16 identities, poisoned invalid-data tails, complete custom up-case mappings, collisions, malformed system streams and entry sets, protected-cluster aliases, cycle/length/allocation failures, cancellation, source errors and retained resource leases.

The enabled native gate requires `mkfs.exfat`, `fsck.exfat`, Sleuth Kit `fls`/`icat` and `sha256sum`; missing tools fail. It is explicitly ignored during portable tests:

```sh
PARTMGR_EXFAT_VOLUME_EVIDENCE=/data/cache/exfat-evidence \
  cargo test --test fs_exfat_volume --all-features --locked -- --ignored
```

Tool overrides are `PARTMGR_EXFAT_MKFS`, `PARTMGR_EXFAT_FSCK`, `PARTMGR_EXFAT_FLS` and `PARTMGR_EXFAT_ICAT`. On 2026-10-07, exfatprogs 1.3.2 and Sleuth Kit 4.14.0 passed this gate. A real mkfs-produced 64 MiB empty volume opens successfully; native fsck accepts the independent 2 MiB payload fixture. `fls` independently resolves nested names; `icat` matches chained payload, nested payload and the initialized contiguous prefix. The receipt records exact commands, versions, source hashes, image hashes and expected/extracted payload hashes at `/data/cache/partmgr-exfat-volume-20261007/exfat-volume-basic-v1.txt`.

Sleuth Kit's forensic extraction returns the physical bytes beyond ValidDataLength. The receipt explicitly marks the independent zero-tail semantic oracle as a gap. The reader's zero-tail behavior is established by specification-based poisoned-tail tests and source-read counters, rather than by agreement with `icat`. Neither p7zip 17.05 nor 7zz 26.02 could open this exFAT fixture.

## Remaining boundaries

This reader does not establish complete cross-file allocation ownership, recursive namespace validity, volume recovery, TexFAT support, editing, or firmware boot correctness. Directory inventories validate their own sets; recursive directory overlap auditing belongs to the tree adapter. Unknown extensions are rejected rather than silently discarded. Raw timestamps and reserved fields are retained but their semantic validity and preservation outcomes need a separate metadata profile. Native payload fixtures currently use 512-byte sectors; the boot parser has a separate native sector-size gate. A mounted independent filesystem oracle for ValidDataLength and larger fragmented/native-populated namespaces remains acceptance work.
