# Common tree capture into exFAT

`ExfatCopyPlan` inventories a common `TreeSource` and feeds deferred indexed `FileRead` streams to `ExfatBuildPlan`. It contains no duplicated exFAT directory or allocation codec. It shares bounded native byte-name conversion and inventory/outcome types with `fs_copy`.

Callers must explicitly select `ExfatCopyMetadataPolicy::ContentOnlyDeterministicDefaults`; `RequirePreservation` fails before output. Actual metadata outcomes identify each source object and class, including absent, known, opaque and uninspectable fields. Source timestamps, ownership, mode, security, attributes and opaque native fields are transformed or omitted under this explicit policy. Uninspectable classes remain unverified rather than being reported as preserved. Destination metadata uses the builder's deterministic defaults. Exact UTF-16 name units survive; byte names require either strict UTF-8 decoding or the explicit ASCII FAT short-alias policy. Destination comparison uses the recommended exFAT up-case table and may reject collisions that a different source namespace admitted.

Hard links/directory aliases, additional/named/system streams, symlinks and special objects fail during inventory. Content-only metadata authorization does not authorize splitting links or silently dropping streams. This implementation does not provide preservation, name mangling or link-flattening policies.

All inventory, continuation tokens and names have explicit bounds. The inventory and metadata report retain a shared reservation; source-owned caches/stream maps retain their own leases. Payloads are not buffered during planning. Short source reads are consumed through a bounded `Arc<FileRead>` adapter. The adapter checks source revalidation and the actual stream identity/size before and after reads; the plan also validates every object and retained stream before and after emission. Cancellation, causal I/O errors and observable source changes fail explicitly. A failure after mutation is a staged interruption, not rollback. Callers must stabilize inputs through the full operation; revalidation and final hashes do not detect every concurrent or transient mutation.

## Example publication path

```sh
cargo run --locked --example filesystem-exfat-copy -- \
  --source-profile ext2 source.img 8192 16777216 destination.exfat 32 \
  --metadata-policy content-only-deterministic-defaults
```

Source profiles are `fat`, `ext2` and `exfat`; output sizes are 32 or 64 MiB. The example uses published virtdisk 0.2.0 and a bounded raw `DiskView`, with no sibling dependency. Each source profile requires its complete clean ownership/reference/state audit before inventory and staging. Existing destinations are refused before creating a temporary output. Capture performs direct filesystem reads; it never extracts a host tree for authoring.

The example creates a fresh same-parent temporary file, emits and verifies the full exFAT image, reopens it through the exFAT ownership audit, and requires a complete clean result. After releasing the exclusive output handle, it uses `persist_noclobber` and flushes the publication directory. Separate report markers distinguish filesystem flush/readback, reopened audit, publication and publication-directory durability. A parent-directory flush failure states that publication occurred and its directory durability is uncertain. The default output is a standalone raw image; optional partitioned staging is described below. Container transactions and firmware boot remain separate gates.

The CLI reports class-level preservation/transformation counts and the selected native-name conversion/comparison policy. The library exposes individual `MetadataOutcome` records for review. The example's source-stability guarantee belongs to its caller.

## Validation

```sh
cargo test --test fs_exfat_copy --test fs_copy --all-features --locked
cargo clippy --test fs_exfat_copy --example filesystem-exfat-copy \
  --all-features --locked -- -D warnings
```

Four portable tests verify a nested 150001-byte deferred payload, short reads, explicit known/opaque/uninspectable metadata outcomes, clean reopening/audit, unsupported streams/links/kinds/preservation, page bounds, invalid byte names, foreign identity, identity/size/generation revalidation, cancellation, budget refunds, causal target failure and identity change after the final readback but before the copy report.

The explicitly invoked native gate requires an evidence directory and all external tools; missing tools fail and leave a failed receipt:

```sh
python3 scripts/filesystem-native-exfat-output-copy.py \
  --output /data/cache/exfat-output-copy-evidence
```

`--tool NAME=PATH` selects installed tool paths. The gate independently creates FAT16 through mkfs.fat/mcopy and classic ext2 through mke2fs/debugfs. Its exFAT source is the versioned independent specification fixture in `fuzz/fixtures`, verified against its prefix, complete-image and archived-generator hashes; no production builder authors that source. Source volumes sit at offset8192 with distinctive prefix/suffix bytes. Every source is independently checked before capture.

For each source profile, two fresh 32 MiB outputs must be byte-deterministic by whole-image hashes. Independent exfatprogs nonrepair fsck and Sleuth Kit recursive names/payload extraction check every ordinary file's exact native path and bytes, including a Unicode ext2 name and the exFAT source's logical ValidDataLength zero tail. Existing destinations are refused unchanged; a source bitmap allocation without an owner is rejected before output. Complete source/framing hashes remain unchanged. Host files serve only as independently generated native-source fixtures and extraction oracles, never as the copy pipeline's input tree.

The 2026-10-08 run used dosfstools 4.2, GNU mtools 4.0.49, e2fsprogs 1.47.4, exfatprogs 1.3.2 and Sleuth Kit 4.14.0. Exact commands, versions, executable/source/binary hashes, fixture provenance, payload hashes and publication reports are retained in `/data/cache/partmgr-exfat-output-copy-evidence/20261007T223503Z-2/evidence.json` (the harness's UTC clock names the artifact directory). Native cross-engine evidence covers 32 MiB outputs; the separate builder gate covers both 32 and 64 MiB. Complete Unicode folded-name comparison still lacks a mounted independent oracle, as documented in the builder profile.


The explicit `--source-profile ext` selects supported immutable ext2/ext3/ext4
sources through `ReadImage`; `ext2` retains its classic profile gate. Both require
complete clean allocation accounting and bounded namespace/maps before staging.
Output reports the accepted source family. Unsupported feature layouts and
journal replay requirements reject. Destination format and explicit content-only
metadata/name policies remain governed by the selected copy operation.


The copy example accepts an optional trailing `--partition-table gpt|mbr`.
It plans the table before staging, places the filesystem at byte offset 1 MiB,
and adds 2 MiB to the requested filesystem size for disk framing. The exclusive
filesystem session is bounded to that region; after emission and verified flush,
its handle drops before a separately opened table session commits. A strict table
reopen checks the selected scheme and exact partition range, followed by a fresh
bounded filesystem allocation audit before publication. GPT uses Microsoft basic
data; MBR uses FAT12 0x01, FAT16 0x06, FAT32 LBA 0x0c or exFAT 0x07.
No firmware boot or atomic transaction across table/filesystem/container layers
is claimed. Unpublished staging is discarded on failure; publication-directory
sync uncertainty remains an already-published outcome.

The frozen native CLI receipt at
`/data/cache/partmgr-fat-exfat-partition-cli-qjackg2g/receipt.json` verifies all
eight FAT12/16/32/exFAT × GPT/MBR images: independent raw table geometry/CRC
checks, nonrepair native filesystem checks and complete TSK extraction of the
512-byte payload. Source/helper/example/tool/binary start/end hashes and exact
commands/output hashes are retained, together with executable copies and the
independent check script. Existing output and invalid-table negative controls
preserve outputs or leave them absent. This is single-file pipeline evidence,
not a broader namespace, physical-device or firmware acceptance gate.


The reproducible combined partitioned-copy gate is:

```sh
python3 scripts/filesystem-native-partition-copy.py
```

Place Cargo/Rust, the C linker, dosfstools `fsck.fat`, exfatprogs `fsck.exfat`,
Sleuth Kit `fls`/`icat` and e2fsprogs `e2fsck`/`debugfs` on PATH. The gate builds
and retains executable copies, authors an independent native-checked FAT12
source, then validates ten FAT12/16/32, exFAT and ext2 × GPT/MBR outputs.
It independently checks reciprocal GPT headers and both entry-array CRCs/types,
MBR ranges/types, nonrepair filesystem checks, exact namespace/payload, unchanged
existing destinations and invalid table profiles. The raw FAT short-name bytes
are `PAYLOAD BIN`; ext2 exact-byte conversion retains that space, whereas FAT
and exFAT alias conversion produces `PAYLOAD.BIN`. Debugfs command success alone
is insufficient: complete extracted bytes must equal the independent model.

The passed frozen-source receipt is
`/data/cache/partmgr-partition-native-pvhzho3d/receipt.json`, with an adjacent
root audit verifying ten images, seventy commands/log hashes, ninety-seven
retained source files, three executable hashes and start/end equality. This gate
creates fresh raw outputs only; container conversion and firmware remain separate.
A deliberately missing Cargo prerequisite fails before build or image output
and retains a failed receipt. Tool invocations preserve their original executable
names, including Rustup dispatch symlinks; resolved paths and digests are recorded
separately. Run with the repository's pinned toolchain first on PATH.
