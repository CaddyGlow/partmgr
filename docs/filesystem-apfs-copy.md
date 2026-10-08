# Offline APFS copy example

`examples/filesystem-apfs-copy.rs` captures one explicitly selected APFS volume
through the common ReadImage tree and authors a fresh native APFS
image. Source bytes must remain immutable throughout inventory and deferred
reads. The source region is bounded by an explicit byte offset/length and volume
object ID; a signature probe does not choose the volume.

```sh
cargo run --example filesystem-apfs-copy -- \
  source.raw 0 67108864 1026 destination.apfs 64 \
  --metadata-policy content-only-deterministic-defaults
```

Append `--partition-table gpt` or `--partition-table mbr` to stage a single
partition at byte offset1048576, with2MiB additional disk space. GPT uses the
Apple APFS type `7c3457ef-0000-11aa-aa11-00306543ecac`, as listed in
[GPT fdisk's type definitions](https://github.com/samangh/gptfdisk/blob/master/parttypes.cc).
MBR uses0xaf; macOS recognition of this MBR profile is not established. The
filesystem writer is dropped before table commit, and table reopen verifies the
scheme, exact extent and type before the filesystem is reopened and audited.
The printed output identifies scheme and region. Omitting the flag keeps raw
standalone output.

Output sizes are1..128MiB. Names retain exact valid UTF8 bytes, sparse logical
content, hardlinks and supported embedded resource forks. Caller-authorized
defaults replace metadata: uid501, gid20, modes0640/0750, timestamp0, fixed new
container/volume UUIDs and label Partmgr authored. Per-object inspection and
transformation outcomes are printed before staging. Unsupported source objects,
oversized forks or unrepresentable names fail preflight rather than disappear.

The example uses a1GiB reservation pool. Source limits are32768 blocks,
256 checkpoint blocks,2048 objects and8192 records; audit limits are4096 objects,
depth32 and1024 findings. Builder limits are4096 objects,8192 occurrences,
1MiB names,32768 blocks and128 entries per page. Read/audit/build work is capped
at512MiB units for each declared operation. These ceilings can reject a larger
namespace even when its payload fits the selected output size.

The destination must be absent. Emission uses a temporary file in its parent
directory and a separately owned bounded Storage session. After builder barriers
and readback, the writable session is dropped, the image is reopened read-only,
and the report verifies its complete SHA/length and clean allocation audit.
All reservations must refund before no-clobber publication and directory fsync.
Causal failures identify the stage; a directory-sync failure after publication
reports uncertain publication durability and the actual destination.

Provisional executable smoke at `/data/cache/partmgr-apfs-cli-acew3jpz/receipt.json`
reauthors the independently authored1,500-file input, producing1501 regular
objects. Independent apfsck accepts the output without diagnostics; TSK extracts
the complete16,397-byte sparse model and8-byte resource fork. Repeating the
command refuses the existing destination and preserves its complete hash.
The earlier3u3g7ybz receipt failed the oversized reservation preflight before
mutation and remains failed evidence. Subsequent frozen acceptance at
`/data/cache/partmgr-apfs-copy-frozen-q6i815vj/receipt.json` binds the executable
to the334-file immutable u0kw6ra0 snapshot, verifies unchanged source/output
images, repeats the complete native payload/fork/checker checks and proves
existing-destination refusal. This establishes the initial raw standalone CLI
profile. TSK's unhashed directory-name
rendering defect prevents treating its fls output as a complete occurrence-name
oracle. Native partitioned/container output evidence, macOS validation, COW/recovery and firmware
remain separate required work.

Live-worktree GPT/MBR smoke evidence at
`/data/cache/partmgr-apfs-partition-smoke-asrabn82/receipt.json` passes both CLI
flows, independently checks primary/backup GPT header and array CRCs plus the
APFS type and exact extent, or the MBR0xaf type/extent, and passes native apfsck
on each extracted64MiB region. Each complete region exactly matches the frozen
standalone output whose sparse payload/resource fork were independently checked.
A frozen compiled-source binding for this new partitioned CLI remains pending;
this live smoke does not establish macOS recognition or firmware behavior.

The repeatable gate `scripts/filesystem-native-apfs-copy.py` accepts an explicit
copy executable, immutable source region/volume, output size and independently
created data/resource-fork model files. It retains inputs, executable, tool
hashes, commands and complete output logs. Example for the independent authored
fixture (the models must come from its input specification):

```sh
python3 scripts/filesystem-native-apfs-copy.py \
  --binary /path/to/filesystem-apfs-copy --source source.apfs \
  --length 67108864 --volume-oid 1026 --output-mib 64 \
  --expected-data sparse-model.bin --expected-fork resource-model.bin \
  --output /path/to/absent/evidence
```

Frozen acceptance at
`/data/cache/partmgr-apfs-partition-native-0_vidunu/receipt.json` passes standalone,
GPT and MBR flows against the independent complete16397-byte sparse model and
8-byte resource fork. All three filesystem regions have identical hashes;
native apfsck accepts each without diagnostics, native icat extracts each full
model, and every existing-destination retry refuses with unchanged image hash.
Independent table checks validate reciprocal GPT headers/arrays/CRCs, type and
range or the single MBR0xaf entry. Root verified246 immutable snapshot sources
and30 retained command logs. Source snapshot is
`/data/cache/partmgr-apfs-partition-source-0_vidunu`; this includes the compiled
copy helper/example and registry dependency lockfile. Full independent namespace
validation, macOS recognition, COW recovery and firmware remain required.
