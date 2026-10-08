# Native FAT reader and builder validation

Run `python3 scripts/filesystem-native-fat.py` from this repository. The harness
builds `filesystem-fat-inspect`, `filesystem-fat-build`, and
`filesystem-fat-build-tree` with
`cargo build --locked` in
`/data/cache/partmgr-native-fat-target` and retains a separate run directory under
`/data/cache/partmgr-filesystem-native-evidence`. Both locations can be overridden
with `--target-dir` and `--output`.

The prerequisites are Cargo/Rust, dosfstools (`mkfs.fat`, `fsck.fat`), and mtools
(`mcopy`, `mdir`). Missing executables produce an explicit `skipped` receipt and
exit code 77; this is never a pass. Any failed command or comparison produces a
`failed` receipt and exit code 1. Success requires all nine reader/builder profiles
and exits 0.

For each of FAT12, FAT16, and FAT32, the harness:

- Creates a fresh image using `mkfs.fat --invariant -F` (1,440, 32,768, and
  131,072 KiB respectively). Production fixture constructors are never used.
- Inserts a 131,089-byte deterministic payload through `mcopy`, covering multiple
  clusters and a partial final cluster, under both `PAYLOAD.BIN` and
  `Long payload name.txt`, and records the external `mdir` listing.
- Runs `fsck.fat -n -v` and requires exit code zero.
- Independently reads BPB root geometry and the known `PAYLOAD.BIN` short directory
  entry in Python to recover first cluster and size. FAT32 uses its root cluster;
  FAT12/16 use the fixed root directory. The fixture is deliberately restricted
  to two files whose slots fit in the first root cluster, so this parser does
  not claim general directory traversal.
- Invokes `filesystem-fat-inspect IMAGE FIRST_CLUSTER SIZE OUTPUT`, checks the
  reported family, and hashes the actual streamed output independently in Python.
  The resulting SHA256 must match the independently generated source payload.
- Invokes `filesystem-fat-inspect IMAGE --list` and requires exactly one
  `native_name=utf16 name_hex=...` result matching the long name encoded as exact
  UTF-16LE bytes. Independently validates the preceding LFN slot ordinals,
  checksum, UTF-16 units, terminator, and padding in Python to identify the long
  file's short slot and its cluster/size. Streams that file and requires its
  content hash to match the independent payload too.
- Requires the image SHA256 before all read checks to equal its SHA256 afterward,
  covering `mdir`, `fsck`, the Python parser, and the production reader.

For the independently checked authoring direction, the harness also:

- Invokes `filesystem-fat-build IMAGE FAMILY PAYLOAD` twice for each family.
  The example creates new files exclusively, emits a root `PAYLOAD.BIN` using
  the public `FatBuildPlan`, and uses conventional 1.44, 32, and 64 MiB images.
- Requires byte-identical image SHA256 values from both deterministic builds.
- Requires `fsck.fat -n -v` to accept the authored filesystem with exit zero.
- Uses `mcopy` to extract the authored file, then compares its SHA256 and the
  independently parsed directory size with the original payload.
- Checks that native listing, fsck, extraction, and entry parsing leave the
  entire authored image byte-identical to its initial hash.

The nested authoring direction retains the six baseline profiles and adds one
`efi-shaped-tree-v1` profile per FAT family:

- Builds an implicit root containing `EFI/BOOT` and twenty empty `ROOT000`
  through `ROOT019` files. The FAT32 root therefore spans multiple clusters.
- Emits `EFI/BOOT/BOOTX64.EFI`, three long names sharing an alias prefix, and
  the exact thirteen-unit name `123456789.txt`, each containing the independent
  payload. The nested BOOT directory also spans multiple clusters. The payload
  is test data, so the EFI-shaped path makes no firmware boot claim.
- Builds the same source inventory in forward and reverse order and requires
  complete image SHA256 equality.
- Requires independent `fsck.fat -n -v` success, retains native root and BOOT
  listings, and extracts every nested file by its native name with `mcopy`.
  Every extracted size and SHA256 must match the independently generated
  payload. Extraction of `ROOT019` must return an empty file.
- Requires all native read checks to leave the complete image hash unchanged.
  These checks cover the selected ASCII long-name, alias collision, directory
  growth, dot-link, and metadata-default formatting profile, not arbitrary
  Unicode namespace equivalence or bootability.

`evidence.json` uses schema version 2 and evidence version `fat-native-v2`.
Each profile has an explicit profile version: `native-root-reader-v1`,
`root-short-builder-v1`, or `efi-shaped-tree-v1`. The tree receipt declares its
`deterministic-defaults` metadata and `ascii-fold-exact-other-utf16` namespace
policies. It records tool paths and version output, source hashes, the built
example hashes, every command/exit code/log location, directory-derived cluster and
size, expected/actual content hashes, exact LFN bytes and name match count, and
before/after image hashes. Images,
source payload, streamed payloads, and complete command logs remain alongside it.
The fsck log supplies its exact dosfstools version; its help output alone does
not print a version.

This gate establishes read-only geometry and explicitly identified file-chain
streaming and one externally created ASCII VFAT long-name sequence on each
family, plus deterministic authoring of fresh images with one canonical root
short-name file, and the nested EFI-shaped ASCII VFAT profile described above.
It does not establish full namespace or VFAT coverage,
whole-volume ownership auditing, general formatting profiles, editing existing
volumes, recovery, Windows servicing, or firmware boot correctness. Firmware
evidence belongs to the separate QEMU/OVMF integration gate.

Verified schema-v2 run: `/data/cache/partmgr-filesystem-native-evidence/20261007T203552Z-2/evidence.json`
passed all nine profiles with dosfstools 4.2 and mtools 4.0.49. This receipt records
the exact source and binary hashes tested; later source changes require a new run.
