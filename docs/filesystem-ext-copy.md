# Common-tree capture into classic ext2

`fs_ext_copy::ExtCopyPlan` inventories an immutable or caller-stabilized
TreeSource and emits a fully initialized, flushed and read-back-verified new
classic ext2 image. Payloads stay deferred. Output publication and partition or
container commits remain separate caller operations.

Regular hardlinks retain one object definition and several namespace links.
Directory aliases/cycles, symlinks, special objects and extra/named/root streams
reject before destination mutation in this copy profile. The source builder
accepts the same explicit classic ext2 geometry as direct authoring.

`ExactBytes` preserves native byte names, including non-UTF8. The caller may
instead select `BytesAndUtf16ToUtf8`; invalid UTF16, names exceeding255 output
bytes, NUL, slash and dot names reject. Source units and byte lengths are checked
before conversion allocation. Converted sibling collisions fail builder preflight.
`ContentOnlyDefaults` requires caller-selected UID/GID, permissions and native
seconds; each source metadata class has a reviewed outcome. Arbitrary metadata
preservation rejects. Hardlink preservation and materialized sparse contents do
not imply preservation of native allocation, permissions or timestamps.

Bounds cover unique objects including root, pages, page size, links, native name
bytes, blocks, work and depth. Inventory reserves16384 bytes per allowed object
plus1024 per allowed link, separately from retained source and builder leases.
File wrappers check source revalidation, original stream identity/length and both
cancellation contexts around each read and extent visit. Source validation before
emission rejects without writes; detected source failure after emission reports
InterruptedWrite and leaves the unpublished image for caller cleanup. No implicit
rollback or publication occurs.

Four portable tests cover hardlink/native-byte round trips, explicit UTF16
conversion, unrepresentable names and additional streams, caller defaults,
short writes, causal write errors, stale source rejection before writes and source
change after the output flush. All retained resource leases refund after drop.

The explicit independent native gate is:

```sh
PARTMGR_EXT_COPY_EVIDENCE=/data/cache/partmgr-ext-copy-native-20261008-final \
E2FSPROGS_TOOLS=/nix/store/k79ra63k4vr2srkwvjrqcppm5pamac5n-e2fsprogs-1.47.4-bin/bin \
cargo test --all-features --locked --test fs_ext_copy \
  independent_e2fsck_debugfs_hardlinks_and_native_byte_payload_copy \
  -- --ignored --nocapture
```

E2fsprogs1.47.4 accepts the new16MiB image with `e2fsck -f -n`; debugfs
independently recovers both native names with exact1024-byte payloads and reports
Links2. Source and output hashes remain unchanged through native validation.
The receipt records tool versions/hashes/commands, binary hash and source hashes
captured before planning and checked again at the end:
`/data/cache/partmgr-ext-copy-native-20261008-final/ext2-copy-V1PUei/receipt.txt`.
The source is an independently assembled64KiB ext2 specification fixture. This
gate proves offline content/name/hardlink capture, not source metadata preservation,
physical durability, all source families or firmware behavior.

Same-binary missing-destination and missing-tools controls both exit101 and produce no passed receipt: `/data/cache/partmgr-ext-copy-negative-8ds4uz84/control.json`. Missing tools may leave the unpublished test staging image; this control does not claim mutation-free gate setup.

## Standalone copy and publication example

```sh
cargo build --locked --example filesystem-ext-copy
/path/to/target/debug/examples/filesystem-ext-copy \
  --source-profile ext2 SOURCE OFFSET LENGTH DEST 32 \
  --metadata-policy content-only-deterministic-defaults --names exact-bytes
```

The example accepts FAT, classic ext2 or exFAT sources with complete clean audits;
it copies the explicitly bounded raw region. Output sizes are16/32/64MiB.
The caller must select `exact-bytes` or `bytes-and-utf16-to-utf8` and explicitly
authorize deterministic UID/GID0, modes0644/0755 and native seconds0. Exact byte
names retain the source contract, including raw FAT short aliases; host-style
name interpretation is not guessed. Plan outcomes are printed before emission.

A same-directory temporary image is flushed, verified and reopened for a complete
ext2 audit before `persist_noclobber` publication. Existing destinations reject
before staging. Publication and parent-directory sync have separate completion
reports; failure after publication identifies uncertain directory durability.
There is no partition, container or boot transaction spanning these stages.

```sh
python3 scripts/filesystem-native-ext-copy.py \
  --output /data/cache/partmgr-native-ext-capture \
  --tools /nix/store/k79ra63k4vr2srkwvjrqcppm5pamac5n-e2fsprogs-1.47.4-bin/bin
```

The native gate independently creates a16MiB ext2 source using mke2fs, with a
350123-byte nested payload, hardlink and exact byte name `x FF`. It frames the
source at offset8192 and captures directly into a32MiB ext2 image without host
extraction during capture. E2fsck accepts both images; debugfs independently
recovers all payloads and confirms Links2. Source, framing and destination hashes
remain unchanged through validation and existing-destination rejection. An
independently inserted source symlink is rejected by the current strict source
audit before destination creation; this is a source-profile rejection, separate
from copy inventory's unsupported-object check. The gate records tool versions,
commands, logs, binary/source hashes and separate layer outcomes. Final receipt:
`/data/cache/partmgr-native-ext-capture-20261008-final/ext2-capture-r6ats8l5/evidence.json`.


The explicit `--source-profile ext` selects supported immutable ext2/ext3/ext4
sources through `ReadImage`; `ext2` retains its classic profile gate. Both require
complete clean allocation accounting and bounded namespace/maps before staging.
Output reports the accepted source family. Unsupported feature layouts and
journal replay requirements reject. Destination format and explicit content-only
metadata/name policies remain governed by the selected copy operation.


Optional `--partition-table gpt|mbr` builds a partitioned raw destination.
The filesystem remains the requested 16/32/64 MiB; the disk adds two MiB, with
one Linux filesystem partition beginning at LBA 2048 (512-byte sectors).
Filesystem emission owns a bounded region, verifies and flushes it, then releases
that session. A separate exclusive table session commits GPT backup/primary/MBR
stages or an MBR table. Strict table reopen verifies the selected range, and the
filesystem is audited again through that bounded region before publication.
Output reports filesystem emission, partition commit/reopen, filesystem audit,
publication and directory durability separately. Boot remains unverified.
A failure before publication drops the unpublished temporary disk; this is
new-output staging, without an atomic transaction or rollback spanning layers.
The default output remains a standalone filesystem.

Functional GPT/MBR CLI evidence is retained at
`/data/cache/partmgr-partitioned-ext-cli-umialil5/receipt.json`: independent raw
field decoding checks LBA/count, while e2fsck/debugfs validate the extracted
filesystem and complete data/hole/unwritten payload. This evidence does not
establish firmware boot or independent container conversion.


After publication, independent container conversion remains a separate stage:

```sh
python3 scripts/filesystem-container-check.py destination.raw --output /data/cache/fresh-conversion-evidence
```

This bounded command requires a fresh evidence directory and qemu-img. It authors
normal and compressed QCOW2 images, checks each container, compares its logical
bytes to the original raw image, converts back and verifies complete size/SHA256.
It retains exact commands/status/stdout/stderr and source/tool/script hashes;
source/tool end hashes must agree. Source stability remains a caller contract.
The successful GPT/MBR runs are retained under
`/data/cache/partmgr-partitioned-ext-cli-umialil5/{gpt,mbr}-conversion/receipt.json`.
Conversion does not commit partitions, install boot files or prove firmware boot.


Filesystem emission/verification, table planning/commit/reopen and filesystem
reopen/audit failures retain a typed stage and their original causal error.
Before publication, the temporary image is dropped on failure; recovery means
rebuilding a fresh unpublished output, not replaying a transaction spanning
partition and filesystem layers. Publication-directory errors retain their
separate already-published/durability-uncertain outcome.


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

The ordinary compressed JFFS2 capture regression independently assembles RTIME
nodes for both byte orders and passes them through ReadImage and ExtCopyPlan.
It verifies a complete256-byte payload after reopening the destination, exact
nonUTF8 nested names, shared hardlink identity, retained reads and refunds.
The destination stores logical content in classic ext2; compression and source
metadata preservation are not promised. This host test has no mounted-kernel
or native-tool acceptance claim.

Frozen modern ext capture receipt
`/data/cache/partmgr-modern-ext-copy-78etehpo/receipt.json` runs the ext source
profile on an independently authored indexed metadata-checksummed image.
E2fsck accepts the32MiB classic destination; debugfs rdump verifies all603 complete
payload/name occurrences against the independent input tree, including its
nonUTF8 name and native shared alias inode/link count. The602 unique files use
explicit destination metadata defaults. Existing-destination refusal preserves
the output hash. All334 compiled snapshot files remain unchanged. Compact
retained maps enable this many-file profile while preserving bounded validation
workspace. This proves content/name/hardlink capture, not native journal mutation,
metadata preservation, controlled performance or firmware acceptance.
