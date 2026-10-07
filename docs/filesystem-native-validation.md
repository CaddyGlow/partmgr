# Native FAT reader and builder validation

Run `python3 scripts/filesystem-native-fat.py` from this repository. The harness
builds `filesystem-fat-inspect` and `filesystem-fat-build` with
`cargo build --locked` in
`/data/cache/partmgr-native-fat-target` and retains a separate run directory under
`/data/cache/partmgr-filesystem-native-evidence`. Both locations can be overridden
with `--target-dir` and `--output`.

The prerequisites are Cargo, dosfstools (`mkfs.fat`, `fsck.fat`), and mtools
(`mcopy`, `mdir`). Missing executables produce an explicit `skipped` receipt and
exit code 77; this is never a pass. Any failed command or comparison produces a
`failed` receipt and exit code 1. Success requires all six reader/builder profiles and exits 0.

For each of FAT12, FAT16, and FAT32, the harness:

- Creates a fresh image using `mkfs.fat --invariant -F` (1,440, 32,768, and
  131,072 KiB respectively). Production fixture constructors are never used.
- Inserts a 131,089-byte deterministic payload through `mcopy`, covering multiple
  clusters and a partial final cluster, and records the external `mdir` listing.
- Runs `fsck.fat -n -v` and requires exit code zero.
- Independently reads BPB root geometry and the known `PAYLOAD.BIN` short directory
  entry in Python to recover first cluster and size. FAT32 uses its root cluster;
  FAT12/16 use the fixed root directory. The fixture is deliberately restricted
  to a single root entry in the first root cluster, so this parser does not claim
  general directory traversal.
- Invokes `filesystem-fat-inspect IMAGE FIRST_CLUSTER SIZE OUTPUT`, checks the
  reported family, and hashes the actual streamed output independently in Python.
  The resulting SHA256 must match the independently generated source payload.
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

`evidence.json` records tool paths and version output, source hashes, the built
example hashes, every command/exit code/log location, directory-derived cluster and
size, expected/actual content hashes, and before/after image hashes. Images,
source payload, streamed payloads, and complete command logs remain alongside it.
The fsck log supplies its exact dosfstools version; its help output alone does
not print a version.

This gate establishes read-only geometry and explicitly identified file-chain
streaming on externally created valid images, plus deterministic authoring of
fresh images with one canonical root short-name file. It does not establish
namespace or VFAT decoding, whole-volume ownership auditing, general formatting
profiles, editing existing volumes, recovery, Windows servicing, or firmware
boot correctness. Firmware evidence
belongs to the separate QEMU/OVMF integration gate.
