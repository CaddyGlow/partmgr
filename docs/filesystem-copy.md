# Content-only FAT tree copy

`FatCopyPlan` copies a `TreeSource` inventory and its deferred file streams into a fresh FAT image. Its supported policy assigns FAT ASCII short aliases, keeps supported native names, and transforms metadata to deterministic FAT defaults. The operation is explicitly content-only: it does not promise native timestamp, permissions, streams, hard-link or other metadata preservation. Planning records preservation decisions and rejects unsupported content before output emission.

The `filesystem-fat-copy` example provides the concrete standalone FAT-region route:

```sh
cargo build --locked --example filesystem-fat-copy
/path/to/target/debug/examples/filesystem-fat-copy [--source-profile fat|ext2|ext|exfat] SOURCE OFFSET LENGTH DEST FAT_FAMILY
```

`--source-profile` defaults to `fat`. The `ext2` profile requires a clean complete
classic ext2 audit; FAT preflight rejects hard links. The `exfat` profile validates
the supported clean namespace/file maps and requires a complete defect-free
whole-volume ownership/state audit before destination creation. Native exFAT valid-data tails become FAT payload
zeros. Neither profile claims metadata preservation.

`SOURCE` is an immutable raw source file; `OFFSET` and `LENGTH` are decimal byte bounds of the selected filesystem. `FAT_FAMILY` selects 12 (1.44 MiB), 16 (32 MiB), or 32 (64 MiB) for the fresh destination. The example requires a complete, defect-free source allocation/state audit, inventories `FatTreeSource`, plans `FatCopyPlan`, and emits directly from positional filesystem streams into a temporary image in the destination directory. It does not extract a host directory tree during capture.

Emission completes the filesystem flush and complete-image verification before publication. The staged image is reopened for a complete, defect-free allocation/state audit. `persist_noclobber` publishes it only when the destination path does not exist, and the parent directory is synced separately. Output identifies each completed layer. A directory-sync failure after publication explicitly reports that the image was published but publication-directory durability is uncertain. This route has no partition-table commit or container transaction; its output is a standalone raw filesystem image.

Source stability remains a caller contract for inventory and every deferred read. Keeping an open positional source handle is not an exclusive lock or immutable snapshot. The native harness checks final whole-file hashes before and after capture and validation, which detects final byte changes but does not establish protection against transient concurrent writes. Use an immutable snapshot or otherwise prevent source mutation throughout the operation.

Run the independent native gate with:

```sh
python3 scripts/filesystem-native-copy.py
```

It defaults to the retained `tree-fat32.img` and `PAYLOAD.BIN` from `/data/cache/partmgr-filesystem-native-evidence/20261007T203552Z-2`. Override their directory with `--fixture`; use `--output` and `--target-dir` to override new run directories and the Cargo build target. Every invocation creates a new disposable run directory and retains its `evidence.json`, command logs, prefixed source, destination and validation payloads. Missing native tools produce `skipped` and exit 77; failed commands or comparisons produce `failed` and exit 1. Only all required checks passing produces `passed` and exit 0.

The gate builds and hashes the actual example binary and records Rust/Cargo, dosfstools and mtools paths, binary hashes and version output, plus hashes of Cargo manifests, Rust sources and the harness. It wraps the source FAT32 image in an 8192-byte prefix and an 8192-byte suffix, then supplies only the bounded interior region to the copy CLI. The destination is a fresh 64 MiB FAT32 filesystem. The receipt keeps filesystem, image-publication, publication-directory-sync, native-validation, partition, container and firmware statuses separate, with complete command arguments, exit codes and hashed logs.

Native validation requires `fsck.fat -n -v` exit zero on both the original source filesystem and the copied destination. It retains `mdir` listings of the source region through mtools' byte-offset syntax and the destination root and nested directory. Only after publication, `mcopy` extracts these five destination names for validation:

- `EFI/BOOT/BOOTX64.EFI`
- `EFI/BOOT/Long boot payload sharing prefix alpha.txt`
- `EFI/BOOT/Long boot payload sharing prefix beta.txt`
- `EFI/BOOT/Long boot payload sharing prefix gamma.txt`
- `EFI/BOOT/123456789.txt`

Every extracted file must match the independent source payload's byte length and SHA256. Full hashes of the original source image, source payload, bounded-region wrapper and destination must remain unchanged through validators. A second capture into the existing destination must fail with a file-exists diagnostic and leave its complete hash unchanged, establishing the example's refusal to overwrite that destination. Validation extraction is separate from the capture pipeline.

Verified run: `/data/cache/partmgr-filesystem-native-copy-evidence/20261007T221017Z-2/evidence.json` passed with dosfstools 4.2 and mtools 4.0.49. It recorded 25 copied files and 67,108,864 verified destination bytes, independent native fsck success, all five payload size/hash matches, existing-destination refusal and unchanged full source/destination hashes. The receipt identifies exact tested source and binary hashes; subsequent source changes need a new run.

This gate establishes the selected ASCII VFAT, content-only, bounded FAT32-region-to-FAT32-image route, including staging and separate flush/publication reporting. It does not establish metadata-preserving copy, arbitrary filesystem pairings, partition installation, power-loss recovery, Windows servicing, or firmware boot. The EFI-shaped path contains deterministic test payload bytes; firmware evidence belongs to the separate QEMU/OVMF integration gate.

The audited exFAT-to-FAT16 gate is reproducible from the retained independent
prefix fixture and its provenance manifest:

```sh
python3 scripts/filesystem-native-exfat-copy.py
```

Place exfatprogs `fsck.exfat`, dosfstools `fsck.fat`, mtools `mcopy`, Cargo and
Rust on PATH. Missing tools fail this explicitly requested native gate. It
reconstitutes the exact SHA256-bound independent 2 MiB exFAT source, checks it
with nonrepair native fsck, frames it in an 8192-byte prefix/suffix, and captures
only the bounded region to FAT16. Native fsck and mcopy validate three
initialized/chained/nested files including a 100-byte valid-data zero tail.
The gate also rejects an existing destination and an independently introduced
lost allocation before output publication, and checks all source/destination
hashes remain unchanged. Receipt/tool/log/source hashes are retained and the
terminal receipt is synced. Its current passed receipt is
`/data/cache/partmgr-exfat-copy-native-evidence/20261007T220823Z-2/evidence.json`.
The allocation audit applies to the selected clean single-FAT basic profile;
TexFAT and unsupported extension profiles remain gated.

Deferred FAT copy reads revalidate their source object both before and after
the complete positional transfer and check cancellation at both boundaries.
The retained stream identity and length are also checked on both sides, including
empty reads. A callback that returns bytes while invalidating its tree or
cancelling the operation therefore cannot produce a successful deferred transfer;
subsequent staging follows the existing interruption reporting contract.


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
