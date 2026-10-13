# Maintenance qualification protocol

This directory documents qualification requirements and bounded NTFS ownership
and native log inspection gates. The [implementation inventory](../../docs/filesystem-maintenance-status.md)
and [maintenance plan](../../docs/filesystem-write-maintenance-plan.md) define
remaining scope. Run only against independently generated disposable fixtures;
the plan authorizes no user-disk erasure or repair.

Current delivery includes P0/P1 foundations and bounded NTFS inspection profiles.
The full maintenance plan remains incomplete. Generate a deterministic working-tree source inventory with:

```sh
python3 scripts/filesystem-maintenance-inventory.py > /tmp/partmgr-maintenance-inventory.json
```

The inventory records source hashes and lexical public module declarations; it
does not verify historical receipts or qualify any native operation.

From the repository root, in its configured development shell:

```sh
cargo fmt -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

Existing independent native gates can establish their documented narrow scopes.
Each evidence path must be fresh and absolute; use a unique suffix for each run.
Tools must be installed before explicitly enabling ignored native gates.

```sh
PARTMGR_EXT_JBD_EVIDENCE=/data/cache/partmgr-maintenance-ext-new \
  cargo test --all-features --locked --lib native_jbd2_codec_e2fsck_replay_and_payload -- --ignored --nocapture

PARTMGR_NTFS_AUDIT_EVIDENCE=/data/cache/partmgr-maintenance-ntfs-audit-new \
  cargo test --locked --test fs_ntfs_audit native_complete_ownership -- --ignored --nocapture

PARTMGR_NTFS_SECURITY_EVIDENCE=/data/cache/partmgr-maintenance-ntfs-security-new \
  cargo test --locked --test fs_ntfs_secure native_secure_ids_sds_sii_sdh_and_ntfs3g_raw_oracle -- --ignored --nocapture
```

These commands are existing source test entry points, not a claim they were run
for the inventory change. Native ext needs e2fsprogs; NTFS audit/security needs
the independently installed ntfs-3g/TSK tools required by each gate. Enabled
missing tools, reused destinations and failed commands must fail visibly.
Do not reuse receipts with changed sources. A native checker's successful exit
alone cannot establish complete payload/metadata correctness.

The explicit resolved ownership gate consumes an independently authored image
with live extension records. It compares whole-volume cluster/free counts and
physical live/extension FILE counts against `ntfsinfo` and a complete native
`ntfscat` MFT dump. It retains compiled sources, binary/tool/image hashes and
command outputs; changed source, missing inputs and reused destinations fail.
This covers allocation and namespace traversal on the supplied fixture, not
complete stream/metadata equality, Windows semantics or maintenance writes.

```sh
PARTMGR_GATE_SOURCE_ROOT="$PWD" \
PARTMGR_NTFS_RESOLVED_AUDIT_IMAGE=/absolute/path/native-extension.ntfs \
PARTMGR_NTFS_RESOLVED_AUDIT_EVIDENCE=/data/cache/partmgr-resolved-audit-new \
PARTMGR_NTFSINFO=/absolute/path/ntfsinfo \
PARTMGR_NTFSCAT=/absolute/path/ntfscat \
  cargo test --all-features --locked --test fs_ntfs_audit_resolved_native \
    native_resolved_allocation_matches_independent_tools -- --ignored --exact --nocapture
```

The native `$LogFile` restart gate consumes a separately acquired Windows-authored
exact journal stream, its bounded raw NTFS partition, and the immutable acquisition
receipt. It also compares the physical page inventory with a separate Python
oracle, including raw page hashes and fixed-up header fields. Generate the oracle
into new files before running the gate:

```sh
python3 integration/maintenance/logfile-page-oracle.py \
  /absolute/path/logfile.bin /absolute/path/physical-page-oracle.tsv
python3 integration/maintenance/logfile-record-oracle.py \
  /absolute/path/logfile.bin /absolute/path/record-oracle.tsv
```

The fixture for this entry point must have offline on-disk version 1.1
restart pages with native clean flags. It validates both restart pages independently,
then selects record 2's unnamed initialized ordinary DATA through the resolved native
reader and compares the selected restart bytes and decoded areas to the supplied
stream. `inspect_ntfs_logfile_pages` also compares every selected physical page
with the direct journal inventory. Separate volume opens have distinct source
scopes; the gate compares native record numbers and sequences across those opens.
It preserves exact volume flags; a clean restart flag remains independent
of the volume dirty flag. Mounted `fsutil` version output cannot substitute for
checking the actual exported restart headers.

```sh
PARTMGR_GATE_SOURCE_ROOT="$PWD" \
PARTMGR_NTFS_LOGFILE_STREAM=/absolute/path/logfile.bin \
PARTMGR_NTFS_LOGFILE_VOLUME=/absolute/path/volume.raw \
PARTMGR_NTFS_LOGFILE_FIXTURE_RECEIPT=/absolute/path/acquisition.json \
PARTMGR_NTFS_LOGFILE_PAGE_ORACLE=/absolute/path/physical-page-oracle.tsv \
PARTMGR_NTFS_LOGFILE_RECORD_ORACLE=/absolute/path/record-oracle.tsv \
PARTMGR_NTFS_LOGFILE_EVIDENCE=/data/cache/partmgr-native-logfile-new \
  cargo test --all-features --locked --test fs_ntfs_logfile_native \
    native_clean_restart_matches_windows_authored_volume -- --ignored --exact --nocapture
```

The gate archives compiled source, binary, raw restart pages and the supplied
acquisition receipt, and checks source/binary/stream/volume/receipt hashes before
and after inspection. The acquisition receipt must independently record Windows
build, geometry, native filesystem commands and immutable image/stream extraction;
this gate binds that evidence without claiming to authenticate arbitrary receipts.
Missing inputs, changed sources and reused destinations fail. The scope is native
restart framing, exact system-stream selection, physical page headers and
clean-flag observation and exact record envelopes/payloads on this fixture.
The record oracle supplies explicit LSNs and independent payload hashes; both
direct and native volume queries must agree. Structural record assembly retains
opaque page bit `0x2` while reporting incomplete page-flag semantic coverage.
Native multipage records remain unqualified. Both tail copies remain independent;
unknown flags retain their raw values and unsupported semantics. Transaction
tables, circular active-window analysis, tail selection, record succession,
redo/undo, recovery, crash behavior and maintenance writes remain unqualified.

The separate dirty 2.0 restart and physical-page gate uses the frozen power-cut capture. It pins
that capture's stream, volume and acquisition receipt hashes, compares both
restart copies through direct/native selection, and compares all physical pages
with an independent Python model. It retains 32 fast-copy candidates without
selecting or applying them. Exact record queries use each explicitly requested restart context; both envelopes,
payloads and decoded checkpoint fields must match separate Python models. Six
explicit open-attribute, names and dirty-page anchors must also match an independent
byte inventory, including multipage envelopes and exact redo hashes. Generic table
links are checked for the open-attribute and dirty-page dumps. The source-owned
loader must load the same references through direct and native-volume APIs,
preserving independent volume flags and skipping the zero-byte transaction
reference. Names bytes and all
entry bodies remain opaque. Checkpoint length equality is asserted only for this
pinned fixture. The extended gate has not been rerun since the original inputs
became unavailable. It preserves differing
LSNs and makes no recovery claim. Generate the independent model into a new file:

```sh
python3 integration/maintenance/logfile-dirty-page-oracle.py \
  /absolute/path/pre-recovery-logfile.bin /absolute/path/physical-dirty-page-oracle.tsv
python3 integration/maintenance/logfile-dirty-record-oracle.py \
  /absolute/path/pre-recovery-logfile.bin /absolute/path/explicit-dirty-record-oracle.tsv
python3 integration/maintenance/logfile-dirty-checkpoint-oracle.py \
  /absolute/path/pre-recovery-logfile.bin /absolute/path/explicit-dirty-checkpoint-oracle.tsv
python3 integration/maintenance/logfile-dirty-table-oracle.py \
  /absolute/path/pre-recovery-logfile.bin /absolute/path/explicit-dirty-table-oracle.tsv
```

Run the gate:

```sh
PARTMGR_GATE_SOURCE_ROOT="$PWD" \
PARTMGR_NTFS_DIRTY_LOGFILE_STREAM=/absolute/path/pre-recovery-logfile.bin \
PARTMGR_NTFS_DIRTY_LOGFILE_VOLUME=/absolute/path/pre-recovery-volume.raw \
PARTMGR_NTFS_DIRTY_LOGFILE_FIXTURE_RECEIPT=/absolute/path/pre-recovery-acquisition.json \
PARTMGR_NTFS_DIRTY_LOGFILE_PAGE_ORACLE=/absolute/path/physical-dirty-page-oracle.tsv \
PARTMGR_NTFS_DIRTY_LOGFILE_RECORD_ORACLE=/absolute/path/explicit-dirty-record-oracle.tsv \
PARTMGR_NTFS_DIRTY_LOGFILE_CHECKPOINT_ORACLE=/absolute/path/explicit-dirty-checkpoint-oracle.tsv \
PARTMGR_NTFS_DIRTY_LOGFILE_TABLE_ORACLE=/absolute/path/explicit-dirty-table-oracle.tsv \
PARTMGR_NTFS_DIRTY_LOGFILE_EVIDENCE=/data/cache/partmgr-native-dirty-logfile-new \
  cargo test --all-features --locked --test fs_ntfs_logfile_dirty_native \
    native_dirty_two_zero_restart_preserves_ambiguity_without_recovery_claim \
    -- --ignored --exact --nocapture
```

The independent ext foreign-format oracle authors footer-free legacy records in
fresh native ext3 images at 1/2/4 KiB and recovers separate clones with e2fsprogs:

```sh
python3 integration/maintenance/ext-foreign-preflight-oracle.py \
  /data/cache/partmgr-ext-foreign-preflight-new
```

The output directory must be new and its absolute path must contain no whitespace,
double quotes or backslashes. The receipt binds the script and tool hashes, exact
arguments, exit codes, full outputs, original images and recovered payloads.
Original dirty images remain unchanged. This establishes an independently
authored native-format/replay corpus, not execution of partmgr's preflight or a
kernel-authored dirty-journal capture. Both are additional gates.

The three-model receipt with captured source and 98 verified artifacts is retained at
`/data/cache/partmgr-ext-foreign-preflight-oracle-20261011-v3/receipt.json`.
The original transaction ID is 1, the scanner boundary is 2, and e2fsprogs leaves
the empty journal sequence at 3 in each geometry. This agrees with the pinned
[Linux recovery restart increment](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/jbd2/recovery.c#L324).
A foreign recovery writer must distinguish the unconsumed scan boundary from the
post-recovery restart ID that invalidates old commit records.

The ignored test
`fs_ext::jbd::foreign::native::native_foreign_preflight_matches_independent_e2fsprogs_overlay`
passed against all three pinned oracle images. Evidence is retained at
`/data/cache/partmgr-ext-foreign-native-20261011-v1`, including compiled sources,
the test binary, corpus, source manifests and per-profile observations. This
qualifies only read-only foreign preflight for this ext3 corpus; recovery writes,
kernel-authored dirty journals and crash interruption gates remain open.

Run the binding and rejection checks with a freshly compiled library test binary:

```sh
python3 integration/maintenance/ext-foreign-preflight-qualify.py \
  --binary /absolute/path/to/partmgr-library-test-binary \
  --corpus /data/cache/partmgr-ext-foreign-preflight-oracle-20261011-v3 \
  --source-root /home/rick/projects-caddy/partmgr \
  --out /absolute/path/to/new-evidence-directory
```

The qualification at
`/data/cache/partmgr-ext-foreign-qualification-20261011-v1/qualification.json`
passed the positive gate and rejected missing receipt, corpus, source, tool and
reused evidence destination bindings. The runner retains all outputs and checks
input hashes before and after execution.

Add `--recovery` to the same command to run the private checksumless recovery gate.
This mode requires an explicit recovery marker and checks all three complete
partmgr output-image hashes against the independent e2fsprogs images. Its first
passing receipt is
`/data/cache/partmgr-ext-foreign-recovery-qualification-20261011-v1/qualification.json`;
the positive gate and all five rejection controls pass. Outputs are disposable
in-memory storage copies archived by the gate. Storage fault tests separately
exercise interrupted writes and barriers; kernel-authored fixtures, native crash
replay and public foreign recovery remain outstanding.

Add `--cuts` with `--recovery` to exercise the modeled persisted-cut matrix.
The implemented matrix comprises 374 fault cases, 21 distinct persisted images
and 84 native commands across 1/2/4 KiB. It independently checks native recovery
sequence 3/4 for each cut while partmgr retains absent restart sequence 3.
`E2FSCK_TIME` supplies deterministic timestamps; comparisons do not mask them.
The final run passed at
`/data/cache/partmgr-ext-foreign-native-cuts-20261011-v3/qualification.json`;
the receipt records the completed matrix and rejection controls. Nine synthetic
recovery and six preflight tests cover additional protocol boundaries, including
the group-zero inode-table relocation guard and a clean final-state counterexample.
The verifier also rejects a consistently rehashed retry image and manifest that
both falsely report sequence 42; it binds the expected sequence to the independent
corpus model. That control is retained at
`/data/cache/partmgr-ext-foreign-sequence-forgery-control-20261011-v1/result.json`.
The matrix models storage cuts; kernel-authored dirty captures, real mount/crash
and hardware behavior, checksummed foreign publication and public sessions remain
separate gates.

For every newly admitted maintenance operation, the runner still to be built
must execute the following protocol:

1. Archive exact source, lockfile, executable/tool hashes and versions; declare
   geometry/features, source generation, allocation/scan/log/scratch budgets,
   fixture parameters and independent expected object/stream/metadata models.
2. Generate native fixtures, retain immutable before images and enumerate every
   object, hardlink and stream. Include both USN states for NTFS, bounded-region
   nonzero offsets, sector sizes, raw/QCOW2 and untouched canaries where supported.
3. Validate read-only plans and rejection cases: unsupported features, wrong
   source/generation, exhausted budgets, missing/wrong keys and cancellation must
   cause zero writes. Preserve findings if the check becomes incomplete.
4. Commit on disposable copies. Inject every write/flush/readback/publication
   interruption, short/torn/full errors, volatile persistence outcomes, cold
   restart and interrupted recovery. Assert declared old/new states and precise
   recovery obligations; never infer payload atomicity from metadata atomicity.
5. Independently check before native repair or mount replay; save both pre/post
   images whenever native tools change them. Compare every payload and native
   metadata field, run native reads/edits, then reopen/audit through partmgr.
6. For NTFS use Windows chkdsk, stream/security APIs, compression/EFS and raw
   backup APIs, fsutil USN and native format/extend/crash replay. Linux tools
   supplement this Windows gate. For ext use e2fsck/debugfs/dumpe2fs and Linux
   mount/replay, including foreign journals. These Windows/mount runners are
   outstanding; the commands above do not implement them.
7. Save exact commands, exits, complete outputs, source/tool/binary/model and
   before/after hashes, rejected controls, resource/throughput measurements and
   exclusions in immutable receipts. A separate verifier must reconstruct and
   compare all models rather than trusting the writer's summaries.

Hardware power-loss, physical flash and QEMU/OVMF firmware boot remain separate
gates. Host Rust tests do not establish Windows servicing/capture or boot.

## Fresh classic ext2 formatting adapter

`tests/fs_maintenance_format_native.rs::native_fresh_ext2_adapter_images` invokes
the public fresh-file formatting adapter for empty 16 MiB images with 1/2/4 KiB
blocks. The exact ignored test requires a fresh absolute
`PARTMGR_EXT_FORMAT_EVIDENCE` directory and `PARTMGR_GATE_SOURCE_ROOT` matching its
compiled source bytes. Build the all-feature test executable with `--release`
before running
`ext-format-qualify.py` with its absolute `--binary`, `--source-root` and fresh
`--out` paths.

The runner requires `e2fsck` and `debugfs`, found through PATH or explicit
`PARTMGR_EXT_FORMAT_E2FSCK` / `PARTMGR_EXT_FORMAT_DEBUGFS` paths. It checks every
profile without repair, inspects root metadata and the complete empty namespace,
and binds actual output hashes, native counts, UUID, features, source inventory,
test executable and tools. Reused output, missing source/tool and stale compiled
source controls must fail. Optimized Python execution is refused because it
would disable verifier assertions.

Recorded formatting timings include creation, sizing, zero scan, emission, file
flush, byte verification and audit on one host run per profile. Cache state is
uncontrolled. This gate does not establish mounted Linux edits, crash recovery,
publication/directory durability, existing-volume format or ext3/ext4 profiles.

## Classic ext2 same-final-group growth

`tests/fs_ext_geometry_grow_native.rs` and `ext-grow-qualify.py` qualify the
bounded classic growth operation against the independently populated native
corpus at `/data/cache/partmgr-ext2-grow-oracle-20261011-v5`. The corpus includes
1, 2 and 4 KiB blocks, two groups, stale dynamic backup counters, native
`resize2fs` references, payloads and hardlinks. The verifier checks the exact
permitted byte changes, bitmap, primary and backup counters, outside canaries,
read-only native consistency, and unchanged inode metadata and payloads.

Build `fs_ext_geometry_grow_native` with `cargo test --release --all-features
--locked --test fs_ext_geometry_grow_native --no-run --message-format=json`
through the repository's development shell. Retain JSON compiler output and
stderr. Pass the resulting absolute executable path to:

```sh
python3 integration/maintenance/ext-grow-qualify.py \
  --binary ABSOLUTE_TEST_EXECUTABLE \
  --source-root /home/rick/projects-caddy/partmgr \
  --corpus /data/cache/partmgr-ext2-grow-oracle-20261011-v5 \
  --out FRESH_ABSOLUTE_EVIDENCE_DIRECTORY
```

The gate binds compiled source, verifier, native tools and corpus hashes. Output
directories must be fresh. Native tools use the pinned e2fsprogs store path
recorded by the corpus. The reference retains raw regular-file resize output
separately because native `resize2fs` truncates its backing; bounded reference
assembly copies only those native filesystem bytes into the extended backing.
This gate establishes offline geometry growth for these profiles. Host cut
tests are separate; native allocation after growth, mounted use, native crash
recovery, new groups and ext3/ext4 growth remain separate qualification work.

## Private owned classic ext3 interruption gate

`ext-owned-oracle.py` independently authors the three classic ext3 profiles and
payload/metadata baselines using pinned native tools and a fixed clock. The
accepted corpus is `/data/cache/partmgr-ext-owned-oracle-20261011-v3`.
Build the library tests with `cargo test --release --all-features --locked --lib
--no-run --message-format=json` through the repository shell, retaining compiler
JSON and stderr. Pass the absolute library-test executable to:

```sh
python3 integration/maintenance/ext-owned-cuts-verify.py \
  --binary ABSOLUTE_LIBRARY_TEST_EXECUTABLE \
  --source-root /home/rick/projects-caddy/partmgr \
  --corpus /data/cache/partmgr-ext-owned-oracle-20261011-v3 \
  --out FRESH_ABSOLUTE_EVIDENCE_DIRECTORY
```

The ignored `native_owned_ext3_allocation_cuts` test covers modeled extension
write/flush cuts and cold owned recovery. Native replay must match all nonjournal
data bytes exactly; independently decoded journal mapping metadata stays in the
comparison. Native checks also cover each repeated-operation image. Source,
binary, verifier, corpus and tool bindings are mandatory. The renewed private fulljournal optimized
run is `/data/cache/partmgr-ext-owned-release-binding-20261011-v10/result.json`.
Its 1,320 cases, 121 distinct persisted images and 817 commands establish scoped
offline evidence, not mounted or hardware crash behavior, all-operation cuts,
modern ext profiles or a public native editor.

## Ordered classic ext3 append/create gate (historical source snapshots)

The ordered gate uses the same pinned corpus v3 and separately compiled ignored
`native_owned_ext3_ordered_allocation_cuts` library test. It requires a fresh
output directory independent of the fulljournal gate:

```sh
python3 integration/maintenance/ext-owned-cuts-verify.py \
  --ordered \
  --binary ABSOLUTE_LIBRARY_TEST_EXECUTABLE \
  --source-root /home/rick/projects-caddy/partmgr \
  --corpus /data/cache/partmgr-ext-owned-oracle-20261011-v3 \
  --out FRESH_ABSOLUTE_ORDERED_EVIDENCE_DIRECTORY
```

For each 1/2/4 KiB profile, append and creation of `/new-ordered` use separate
successful baselines and complete write/flush fault matrices. Immediate and
volatile models retain every case, including prefix-zero/half/full failed writes
and failed flushes with and without persistence. All manifest references remain
present when persisted images deduplicate.

The verifier independently derives permitted old-state differences from the
original allocation bitmap and successful regular-file mapping: originally free
regular data blocks and the exact old EOF suffix. All other old homes remain
exact. New outcomes require exact homes. Only independently decoded journal data
is excluded; journal mapping metadata stays in the comparison. Native replay and
Rust cold retry must agree on the unambiguous old/new outcome, complete visible
payload and unrelated inode/hardlink metadata. Source, binary, corpus, verifier,
tools, artifacts and negative controls remain mandatory.

The public ordered source-bound result is
`/data/cache/partmgr-ext-ordered-release-binding-20261011-v2/result.json`:
2,448 cuts, 209 distinct persisted preimages and 1,354 commands. Independent
baseline descriptor checks prove regular-file data is absent from redo in all
six ordered profiles. Three prior-fulljournal baselines are rejected by that
policy check at
`/data/cache/partmgr-ext-ordered-redo-negative-20261011-v2/result.json`.
Missing/stale sources, reused output and altered-verifier controls also reject.
The gate now routes ordered success, fault dispatch, cold recovery and reads
through the public `ExtJournalSession` API. It also archives three
successive operations in the same public owner per geometry: append `/payload`,
create `/new-ordered`, then append `/new-ordered`. Those nine snapshot checks are
separate from operation interruption coverage. The public ordered v2 native receipt includes those nine same-owner snapshots
and 1,354 recorded commands. Renewed private fulljournal v10 also passes with
1,320 cuts, 121 preimages and 817 commands. The failed fulljournal v9 inventory
mismatch remains retained; the verifier now binds the public consumer test source.

The `std` public `fs_ext::ExtJournalSession` now declares profile manifest
version seven. Its filesystem allowlist is unchanged: Linux revision one,
128-byte inodes, 1/2/4 KiB blocks, feature words 4/2/1 with transient RECOVER,
and an internal checksumless journal without REVOKE and first block one.
Alongside ordered regular-file append/create/truncate, `write_at` and `extend_sparse`, it exposes `create_directory`,
`rename`, `hard_link`, `unlink_file`, `remove_directory`, `create_symlink`,
`replace_symlink_target`, `unlink_symlink` and `read_symlink`. The manifest-seven
symlink integration passes all five source-bound host checks; source-bound native interruption/recovery, adversarial controls and final rehash pass for the archived manifest-seven snapshot.
The [current implementation checkpoint](../../docs/filesystem-maintenance-status.md#current-implementation-checkpoint--2026-10-12)
also distinguishes unintegrated preallocation, counter-repair and NTFS drafts. Names are exact bytes; creation
uses explicit native metadata. Rename refuses existing destinations and cycles.
Deletion requires explicit native time, nonzero and at least the inode count;
source-owned planner kind guards distinguish regular unlink from empty-directory
removal before publication. No recursive deletion or payload wiping is implied.
Successful mutation/recovery invalidates handles; errors can conservatively
retain `NeedsRecovery`. Physical controller and planner authority remain private.

The subsequent private classic namespace controller accepts sealed mkdir,
rename/move, file unlink and empty-directory deletion batches. All directory and
indirect blocks remain journal metadata; an independent original-owner scan
excludes full regular-file payload blocks, including EOF tails, from redo.
The host matrix covers 984 modeled interruption cases across 1/2/4 KiB with cold
recovery. All five host/portable checks pass at
`/data/cache/partmgr-maintenance-ext-namespace-checks-20261011-v3/result.json`.

The private native namespace release gate has now passed at
`/data/cache/partmgr-ext-namespace-release-binding-20261011-v2/result.json`:
6,024 modeled cases, 454 distinct persisted preimages, 2,700 native commands,
8,143 outer artifact hashes and 203 compiled-source bindings. Both the Rust
positive and independent native verifier exit zero; missing/stale-source and
reused-evidence controls exit 101, while altered-verifier and missing-corpus
controls exit one. All five host/portable checks for that snapshot pass at
`/data/cache/partmgr-maintenance-ext-namespace-checks-20261011-v3/result.json`.

The failed first native v1 precheck (exit 12) remains retained. V2 permits that
pre-replay status only for the narrowly classified combination of directory
corruption, aborted checking and a recovery obligation; six such diagnostics
are retained. Native replay, strict post-replay checking and exact home-byte
comparisons remain mandatory. This is offline modeled persisted-byte evidence,
not mounted-kernel or hardware-crash qualification.

Final receipt/artifact rehash passed at
`/data/cache/partmgr-ext-namespace-final-rehash-20261011-v2.json`, confirming
347 host-source hashes, 203 compiled sources and all 8,143 native artifacts.
All eight additional adversarial controls passed at
`/data/cache/partmgr-ext-namespace-negative-controls-20261011-v2/result.json`
with 6,011 retained artifact hashes: omitted matrix row, forged outcome, altered
unrelated payload, deletion time, directory links, free-space counter, regular
payload redo and omitted new-directory redo. The last control reconstructs valid
journal framing and fails specifically on missing directory metadata. Original
artifacts remain unchanged; the failed first control-harness attempt is retained.
The renewed public six-operation namespace v3 gate passed for the corrected
source snapshot at
`/data/cache/partmgr-ext-public-namespace-release-binding-20261011-v2/result.json`:
6,024 modeled cases, 454 persisted preimages, 2,700 native commands, 8,147 outer
artifact hashes and 205 compiled sources. Both positive controls pass; all five
fatal missing/stale-source, reuse, altered-verifier and missing-corpus controls
reject. Its earlier v1 receipt retains its archived source scope.

The corrected public namespace v4 release gate passed at
`/data/cache/partmgr-ext-public-namespace-v4-release-binding-20261011-v2/result.json`:
2,136 modeled cases, 162 persisted preimages, 1,410 native commands, 27 same-owner
snapshots, 4,589 outer artifact hashes and 205 compiled sources. Populated
cross-parent directory moves and final indirect-map unlink are checked at
1/2/4 KiB, alongside nine successive public operations per geometry. Both
positive controls pass; missing/stale-source and reused-evidence controls exit
101, while altered-verifier and missing-corpus controls exit one. All five
corrected host/portable checks pass at
`/data/cache/partmgr-maintenance-ext-public-namespace-checks-20261011-v2/result.json`.

The failed first v4 release and intermediate diagnostic results remain retained:
canonical verifier corrections handle hyphenated operation names and exclude
the journal inode from ordinary regular-payload classification. Diagnostic
success alone was not acceptance; the corrected release reran the source-bound
gates. All six additional v4 adversarial controls reject at
`/data/cache/partmgr-ext-public-namespace-v4-negative-controls-20261011-v1/result.json`
(SHA-256 `758aeafbd120e3270ef23409d08995b88f5b6a7ee06b20e5d6569d46436dee2d`),
retaining 2,793 artifact hashes. They cover an omitted matrix row, forged outcome,
parent link count, moved-tree `..`, indirect bitmap release and raw inode
preservation. The combined final rehash passed at
`/data/cache/partmgr-ext-public-namespace-final-rehash-20261011-v1.json`,
verifying 349 host-source hashes, 205 compiled sources per native gate and all
12,736 outer native artifact hashes. The accepted v3 receipt SHA-256 is
`d850775338cdecbe1fa0650b5fe0f6732818ee51f1454efa3854564ec0156189`;
the accepted v4 receipt SHA-256 is
`da80d3711698e3bd9c2689cb07ff3caed793a62b619d5132e98eeb428b08b130`.
All eight renewed v3 adversarial controls reject at
`/data/cache/partmgr-ext-public-namespace-negative-controls-20261011-v1/result.json`
(SHA-256 `3b8ef65eb45829e19628182d51f3d9367f9af01790ba5a156d6a2990c36bf73d`),
retaining 6,027 artifact hashes. They cover an omitted matrix row, forged outcome,
unrelated payload, deletion time, link count, free-space counter, regular-data
redo destination and omitted mkdir redo. The exact archived runner/index match
the accepted inputs, and the original artifacts remain unchanged.

The public forced-directory-growth gate passed at
`/data/cache/partmgr-ext-directory-growth-release-binding-20261011-v1/result.json`:
2,280 modeled interruption cases, 178 distinct persisted preimages, 1,430 native
commands, 4,655 outer artifact hashes and 207 compiled sources. Native-authored,
fully packed destination directories force public rename to grow from one to two
direct blocks or from twelve to thirteen blocks across the single-indirect
boundary at each 1/2/4 KiB geometry. Independent packing proofs establish that no
original slot can hold the 255-byte destination name. New directory blocks and,
when needed, the indirect map block are metadata redo; original regular payload
blocks remain excluded. Every actual write/barrier is cut under immediate and
volatile persistence, including failed-flush persistence and zero/half/full torn
writes. Public cold recovery must produce exactly the old or complete new home
image outside journal data allocation. Native replay, filesystem checks, mapping
and full unrelated payload comparisons independently verify those outcomes.
The independently expanded native directory supplies a semantic layout reference,
not an atomic native rename oracle.

All five host/portable checks pass at
`/data/cache/partmgr-maintenance-ext-directory-growth-checks-20261011-v1/result.json`,
including ten public consumer tests. Operation planning now uses the minimum of
the caller and session `file_blocks` limits; the session previously replaced the
caller's narrower ceiling. Complete ownership auditing retains the session audit
limits. Final rehash passed at
`/data/cache/partmgr-ext-directory-growth-final-rehash-20261011-v1.json`, verifying
351 host-source hashes, 207 compiled sources and all 4,655 native artifact hashes.
The native receipt SHA-256 is
`c3aadbb5126d3e1e3f11c0adba043c09a59c0c7c580f36ac5ac574925c152996`;
the host receipt SHA-256 is
`cc4a9a251ab0612f0334c565517d5bba6e48ece895b28827ba9852e71f635d05`.
All seven additional adversarial controls reject at
`/data/cache/partmgr-ext-directory-growth-negative-controls-20261011-v1/result.json`
(SHA-256 `6cce2fb7a23fe7307aa5f3151ce85f1c04e26a65db67e51ad7f2575dc8e6194a`),
retaining 3,480 rehashed artifacts and the exact archived runner; original inputs
remain unchanged. They cover missing rows, forged outcomes, altered directory
packing, new indirect allocation, original payload EOF slack and coherent omission
of directory or indirect metadata redo. Both omission controls fail specifically
at the required-metadata assertion. The altered-packing control rejects at
directory-graph preservation before reaching the usable-slack predicate.
This receipt qualifies these two forced-growth operations at its own
source snapshot; previous append/create and namespace receipts retain their exact
archived source scopes.

Public `ExtJournalSession::truncate(file, length, planning, cancellation)` now
accepts strictly smaller sizes through a current same-owner handle under manifest
three, with the same filesystem/journal allowlist as manifest two. Zero and
block-aligned truncations release detached data/indirect blocks through metadata
redo; a partial EOF in a hole stays a hole. For a mapped partial EOF, one block
from ORIGINAL audited-free space receives the retained prefix and a zero suffix.
The metadata transaction replaces only the final retained mapping and releases
the replaced original and detached blocks. Hardlinks retain the same inode and
observe the same new length; native identity, generation, ownership, times and
link count remain unchanged.

Original regular payload blocks, including formerly visible suffixes and EOF
slack, are neither overwritten nor journaled. Fresh COW data flushes and reads
back before metadata commit. A leased exact original-block guard is checked in
planning and again before first publication; full prospective auditing and
operation-specific retained-map checks precede writes. Allocation/release edits
coalesce only for this sealed ordered transaction. External-undo and private
full-journal truncate behavior remains unchanged. A mapped partial truncation
can refuse for lack of ORIGINAL free space even when it would release blocks;
same-plan releases cannot supply COW storage while OLD remains reachable.

The corrected public truncate gate passed at
`/data/cache/partmgr-ext-truncate-release-binding-20261011-v3/result.json`:
5,784 modeled cuts, 439 persisted preimages, 6,125 native commands, 18,454 outer
artifact hashes and 209 compiled sources. Six success cases at each 1/2/4 KiB
geometry cover zero, direct boundary, indirect-root removal boundary, mapped
partial direct/indirect and partial EOF hole. Three fully allocated models
separately verify zero-write ENOSPC refusal. Public cold recovery and native
replay independently select OLD or complete NEW with full alias payload reads,
allocation/mapping checks and filesystem validation. OLD excludes only journal
data and the independently proven originally-free COW block; every original
regular block and metadata byte remains exact. NEW requires exact final homes
outside journal data, including unchanged former regular physical bytes and the
new prefix/zero tail. Independent redo checks exclude original regular and fresh
COW data while requiring changed metadata destinations. Native truncate's own
tail/mapping policy is not a byte-exact oracle for this COW policy.

All five host/portable checks pass at
`/data/cache/partmgr-maintenance-ext-truncate-checks-20261011-v3/result.json`,
including thirteen public consumer tests. Final rehash passed at
`/data/cache/partmgr-ext-truncate-final-rehash-20261011-v1.json`, verifying
353 host-source hashes, 209 compiled sources and all 18,454 native artifact hashes.
The native receipt SHA-256 is
`b7619fe7abf84f48cfa4fcb8cf88571e60ec2e894f5307594f8523c3aed1b253`;
the host receipt SHA-256 is
`cc4a9a251ab0612f0334c565517d5bba6e48ece895b28827ba9852e71f635d05`.
The failed v2 verifier receipt remains retained: it treated sparse-hole sentinel
zero as a physical regular block and rejected legitimate primary-superblock redo
at 2 KiB. The corrected verifier excludes that sentinel; a fresh v3 build, all
checks and the native gate passed. All eleven additional adversarial controls
reject at
`/data/cache/partmgr-ext-truncate-negative-controls-20261011-v1/result.json`
(SHA-256 `dc5c6f62e7f44c237b99cfd01c670727b1f9b0b1eba6df8b8287e9b55acc7be6`),
retaining 20,981 output artifact hashes; final rehash confirms the original
accepted artifacts remain unchanged. Controls cover a missing matrix row, forged
decision, original EOF slack, COW prefix, COW zero tail, free counter, hardlink
count, original regular-data redo, COW-data redo, OLD visible tail and sparse-hole
sentinel zero treated as physical block zero. Both redo controls reject at the
required payload-exclusion diagnostic. The last two reject at exact home-image
comparison beyond the permitted COW mask. Independent rehash passed for all
20,981 control-output hashes and the exact archived runner; original accepted
artifacts remain unchanged. Earlier manifest-two receipts retain their exact
archived source scopes;
this receipt qualifies ordered truncate at its own source snapshot.

The ignored `native_owned_ext3_ordered_truncate_cuts` gate uses
`PARTMGR_EXT_TRUNCATE_CORPUS`, `PARTMGR_EXT_TRUNCATE_EVIDENCE` and
`PARTMGR_GATE_SOURCE_ROOT`. Its corpus generator is `ext-truncate-oracle.py`;
`ext-truncate-cuts-verify.py` independently verifies the bound images, redo and
native replay. `namespace-cuts.tsv`, `enospc.tsv` and COW observations preserve
fault outcomes, refusal evidence and original/fresh block provenance.

Public `ExtJournalSession::hard_link(source_parent, source_name,
destination_parent, destination_name, planning, cancellation)` now creates an
exact byte-name reference to an existing regular inode under manifest four,
with the same filesystem/journal allowlist as manifest three. Current owner-bound
parents resolve the source; actual inode mode must be regular. Existing
destinations reject, including an existing alias of the same inode. Source native
inode bytes remain exact except link count: length, mapping, generation,
ownership, mode and timestamps are preserved, as is the entire original physical
payload including EOF slack. Timestamp preservation is explicit; this operation
does not adopt an implicit kernel ctime update.

All aliases share one inode. Later append or COW truncate through any current
alias changes the content seen through every surviving alias. Nonfinal unlink
releases no allocation; final unlink releases the inode/data once. A roomy
parent succeeds with zero free blocks; packed-parent growth requires originally
free directory/map storage and can refuse before writes. Source inode allocation
and parent link counts remain unchanged. Metadata-only redo excludes original
regular physical data. Success invalidates handles; uncertain dispatch retains
`NeedsRecovery` through explicit recovery and profile revalidation.

Creation uses an explicit 32,000-link EXT2-compatible operation policy:
31,999 to 32,000 is admitted, while another creation rejects before writes.
This is not the native ext3/ext4 on-disk maximum; the Linux ext4 driver supports
a wider 65,000-link limit. Wider creation policies remain unqualified. Existing
higher-count volumes are not newly rejected during read-only inspection or unlink.
A complete audited 4 KiB host fixture contains 31,999 actual unique references;
it verifies the boundary without forging inode counts. Independent public tests
also cover all block sizes, shared alias mutations, exact physical preservation,
zero-free roomy/packed cases and refusal/resource behavior.

The source-bound public hardlink gate passed at
`/data/cache/partmgr-ext-hardlink-release-binding-20261011-v1/result.json`:
3,960 modeled cuts, 298 persisted preimages, 2,481 native commands, 7,719 outer
artifact hashes and 211 compiled sources. Same-parent, cross-parent and forced
one-to-two/twelve-to-thirteen-block destination growth run at 1/2/4 KiB. Every
actual write/barrier is cut under immediate/volatile persistence, failed-flush
persistence and zero/half/full write prefixes. Public cold recovery and native
replay independently establish exact OLD or complete NEW homes outside actual
journal data; there is no regular-data, COW or unreachable-payload mask. Native
checks verify source inode preservation except count, namespace topology, all
alias payloads/physical slack, allocation counters and required new directory/
indirect metadata redo, while excluding regular-data redo destinations.

All five host/portable checks pass at
`/data/cache/partmgr-maintenance-ext-hardlink-checks-20261011-v4/result.json`,
including eighteen owned consumer tests and one external-undo smoke test.
Final rehash passed at
`/data/cache/partmgr-ext-hardlink-final-rehash-20261011-v1.json`, verifying
355 host-source hashes, 211 compiled sources and all 7,719 native artifact hashes.
The native receipt SHA-256 is
`85660ef3e612355c6c8623e6773685d2d02babe0118feba3f5b2306dc79591ab`;
the host receipt SHA-256 is
`cc4a9a251ab0612f0334c565517d5bba6e48ece895b28827ba9852e71f635d05`.
All ten additional adversarial controls reject at
`/data/cache/partmgr-ext-hardlink-negative-controls-20261011-v1/result.json`
(SHA-256 `adeb245dc00d6a775f5a34d0528f901f1be1041e25a67f5baf37e09d6f0cf7bc`).
Independent rehash passed for all 7,423 output artifacts and the exact archived
runner; original accepted inputs remain unchanged. Missing new-directory and
indirect redo controls reject specifically at required-metadata checks;
regular-data redo rejects at the payload-destination exclusion, and altered OLD
homes reject at exact home-image comparison. Earlier manifest-three
truncate and manifest-two namespace/growth receipts retain their exact archived
source scopes; this receipt qualifies hardlink at its own snapshot.

Manifest five adds public `ExtJournalSession::write_at(file, offset, input,
planning, cancellation) -> io::Result<u64>` with the same filesystem/journal
allowlist as manifest four. A current owner-bound regular-file handle authorizes
a nonempty exact input wholly within existing EOF; checked endpoints refuse
overflow and implicit extension. Success returns the entire snapshotted declared
input length after durable commit, never a short-success count. All aliases share
the mapping change. Logical length, native generation, ownership, mode, times and
link count remain exact; mutation invalidates prior handles.

Each touched logical block receives distinct originally audited-free storage.
Mapped replacements copy every unaffected byte, including physical EOF slack,
then apply the exact input intersections. Touched holes start as zeros and only
touched blocks materialize; untouched mappings remain exact. Metadata publication
updates mapping/allocation/counter/sector fields and releases replaced originals.
Every original regular physical block remains unchanged. Neither original nor
fresh COW data is encoded in metadata redo. Same-plan releases cannot supply COW
space while OLD remains reachable, so net-zero overwrite may refuse ENOSPC.

The session's immutable-length adapter pins the wrapper/planner/success count;
input identity and declared length are checked throughout reads. Short reads
are accumulated; premature zero or oversized reads, backend errors and
cancellation retain their causes. Full prospective ownership auditing and
operation-specific evidence validate original/final maps, exact touched coverage,
original-free destinations and complete replacement bodies. Leased exact source
block guards are rechecked before first publication and after fresh data flush/
readback before mutation commit. Uncertain publication retains `NeedsRecovery`;
explicit owned recovery establishes the old or complete new mapping. Finite
memory/work/journal/physical-footprint ceilings cover simultaneous input snapshots,
guards, maps, audit, data and metadata; whole-file operations may require larger
explicit bounds than one-block operations.

All five host/portable checks pass at
`/data/cache/partmgr-maintenance-ext-overwrite-checks-20261011-v4/result.json`.
Twenty-four public owned consumer tests include arbitrary multiblock/direct-to-
indirect writes, full-file and EOF boundaries, partial/full holes, aliases, exact
original physical payload/slack preservation, immutable count sampling, source
and input failures, cancellation/budgets, genuine ENOSPC and cold recovery.
Private tests additionally reject forged range, map and replacement-body evidence.

The source-bound public range-overwrite gate passed at
`/data/cache/partmgr-ext-overwrite-release-binding-20261011-v2/result.json`
(SHA-256 `c6ffa3c412d1f0a4c4a63e8d4eeb36357f51cc52288fbe26092b5eff1ffcc492`):
6,336 modeled cuts, 484 persisted preimages, 6,797 native commands, three zero-write
ENOSPC refusals, 20,535 outer artifact hashes and 219 compiled sources. Both Rust
and independent native positive controls pass. Missing-source, reused-evidence
and stale-source controls reject with exit 101; altered-verifier and missing-
corpus controls reject with exit one. The failed first outer receipt remains
retained: its positive gate passed, but runner binding failed; fresh v2 acceptance
includes the corrected runner binding. Final rehash passed at
`/data/cache/partmgr-ext-overwrite-final-rehash-20261011-v2.json`, verifying
358 host-source hashes, 219 compiled sources and all 20,535 outer artifact hashes.
All thirteen additional adversarial controls reject at
`/data/cache/partmgr-ext-overwrite-negative-controls-20261011-v1/result.json`
(SHA-256 `8a4146cfa00fcd857615e923d04cb599e43cd4e8ea9daaa9ec5e72e364b2d7b5`),
retaining 28,456 output artifact hashes. Controls cover missing rows, forged
outcomes, original EOF slack, COW prefix/body/suffix, bitmap accounting, inode link
count, original/COW data redo, omitted bitmap redo, OLD visible tail and physical
block zero incorrectly masked as a hole sentinel. Both data-redo controls fail
specifically at regular-payload exclusion; omitted bitmap redo fails because a
home change lacks redo. OLD-tail and sentinel controls fail exact home comparison
beyond the permitted fresh-COW mask. The runner verifies original accepted
artifacts remain unchanged. Independent rehash passed at
`/data/cache/partmgr-ext-overwrite-negative-controls-rehash-20261011-v1.json`,
covering all thirteen controls and 28,456 output hashes, the exact receipt and
archived runner (SHA-256
`0308006061e842263163b91057f23f1a727fb291cbd1a0dd4a47f6304bfdbc6f`).
This completes the scoped manifest-five overwrite evidence; subsequent
manifest-six sparse extension has scoped host/native and adversarial qualification
bound to its exact archived revision. Manifest-seven symlinks pass host checks; source-bound native interruption/recovery, adversarial controls and final rehash pass for the archived manifest-seven snapshot.

The ignored `native_owned_ext3_ordered_overwrite_cuts` gate uses independent
`ext-overwrite-oracle.py` / `ext-overwrite-cuts-verify.py` tools and
`PARTMGR_EXT_OVERWRITE_CORPUS`, `PARTMGR_EXT_OVERWRITE_EVIDENCE` and
`PARTMGR_GATE_SOURCE_ROOT`. Every actual write/barrier is cut under the declared
immediate/volatile, failed-flush and zero/half/full-prefix models. Rust cold
recovery and native journal replay independently establish OLD or complete NEW.
OLD permits only actual journal data and independently proven originally-free
final COW destinations; original regular bytes, including EOF slack, are never
masked. NEW preserves exact successful homes outside journal data and validates
independent input overlays, alias contents, maps and allocation accounting.
Retained redo inspection excludes original/final regular data and requires changed
mapping/bitmap/inode metadata. Earlier manifest-four hardlink, manifest-three
truncate and older namespace/growth receipts retain their exact archived source
scopes; this receipt qualifies range overwrite at its own source snapshot.

Manifest six adds public `ExtJournalSession::extend_sparse(file, new_length,
planning, cancellation)` with the same filesystem/journal allowlist as manifest
five. It requires a strictly larger logical length through a current owner-bound
regular-file handle. All newly visible bytes are zero and aliases share the new
length. This creates holes rather than reserving payload capacity; `write_at`
continues to require a range wholly inside the existing EOF.

Empty/aligned EOF and partial EOF already in a hole preserve all old mappings and
append holes without regular data writes. A mapped partial EOF always receives
one fresh originally audited-free COW block, even for same-block growth: its old
visible prefix is copied and the entire remainder zeroed. Original physical data,
including hidden EOF bytes, remains exact. The old tail block is released only
in committed metadata. Native identity, generation, ownership, mode, times and
link count stay unchanged; sectors reflect actual allocations, not logical holes.
Original indirect-node identities, including admitted empty nodes, are retained;
unexpected pointer-metadata allocation/release refuses. No large-file feature is
implicitly enabled. Native length/pointer representation and logical `file_blocks`
ceilings remain explicit; long holes still consume bounded inventory resources.

Mapped partial extension requires original-free storage and can refuse ENOSPC
while aligned/hole extension succeeds on a fully allocated volume when no metadata
allocation is needed. Separate sealed sparse evidence proves exact original/final
maps, zero/one data role, original-free tail, copied prefix/zero suffix and native
metadata preservation under the complete prospective audit. Existing controller
checks exact leased guards before any publication and after fresh data durability
before mutation commit. Errors after attempted publication retain `NeedsRecovery`;
explicit recovery selects the old or complete new length/map before readiness.

All five host/portable checks passed for the archived manifest-six revision at
`/data/cache/partmgr-maintenance-ext-sparse-checks-20261011-v2/result.json`.
Twenty-eight public owned consumer tests include all block sizes, empty/aligned/
hole/mapped partial EOF, same-block and direct/single-indirect crossings, aliases,
exact old physical bytes, raw sectors/empty-indirect identity, genuine no-free
contrasts, strict bounds/budgets/cancellation and source failures before/after data
with cold recovery. A private focused test rejects eight forged sparse proofs and
accepts two valid controls. The source-bound native interruption gate passed at
`/data/cache/partmgr-ext-sparse-extension-release-binding-20261011-v3/result.json`
(SHA-256 `c5f7255139a2fc82fbf0e629df2d065c316b393046bf15aa54e4e527d19f8fba`).
It retains 8,808 cut cases, 616 distinct preimages, 10,050 independent native
commands, three ENOSPC cases and 30,010 outer artifact hashes. These cover
1/2/4 KiB blocks, empty/aligned/hole/mapped EOF and no-free distinctions.
Independent final rehash passed for 361 host sources, 222 compiled sources
and all 30,010 native artifacts at
`/data/cache/partmgr-ext-sparse-extension-final-rehash-20261011-v3.json`.
Sixteen adversarial verifier controls also pass at
`/data/cache/partmgr-ext-sparse-extension-negative-controls-20261011-v1/result.json`
(SHA-256 `c3abc4a6a795e1b4ed3daaf5552cae4b63e8736f0f92387ce730aa35e1065a93`),
with 32,287 artifacts independently rehashed at
`/data/cache/partmgr-ext-sparse-negative-rehash-20261011-v1.json`.
This closes the scoped manifest-six sparse-extension milestone. These receipts
qualify their exact archived revision; the subsequent manifest-seven symlink
integration requires fresh host/native qualification. Earlier interrupted attempts
are retained without acceptance.

The ignored `native_owned_ext3_ordered_sparse_extend_cuts` gate uses
`PARTMGR_EXT_SPARSE_CORPUS`, `PARTMGR_EXT_SPARSE_EVIDENCE` and
`PARTMGR_GATE_SOURCE_ROOT`, with `ext-sparse-extension-oracle.py` and independent
`ext-sparse-extension-cuts-verify.py`. Required OLD comparison may exclude only
actual journal data and the exact zero/one originally-free mapped-tail COW block;
holes are not physical block-zero masks. NEW must match strict final homes outside
journal data, complete alias prefix/zeros, map/bitmap/sectors and unchanged original
physical payload. Earlier manifest-five overwrite and other accepted receipts
retain their exact archived source scope; they do not qualify this new revision.

Manifest seven integrates `create_symlink`, `replace_symlink_target`,
`unlink_symlink` and `read_symlink`; existing `rename` also handles unfollowed
symlinks. All five required host/portable checks pass against the same 365-source
snapshot at `/data/cache/partmgr-maintenance-ext-symlink-checks-20261011-v5/result.json`;
source-start, source-end and live source hashes independently match. Source-bound native
interruption/recovery, adversarial controls and final rehash pass for this
archived manifest-seven snapshot. The filesystem and
journal feature allowlists remain unchanged.

Canonical fast targets contain 1..59 non-NUL bytes inline; canonical slow targets
contain 60..blocksize-1 bytes in one direct block, with a native terminator.
Empty targets, embedded NUL, lengths at least one block and unqualified short
block-backed source layouts are refused. Target bytes remain uninterpreted:
dangling paths, slash/dot components, absolute paths, non-UTF8 bytes and cycles
are not followed. Parent components must resolve as directories. Creation uses
explicit native metadata; replacement preserves inode identity, generation,
native times and every alias across fast-to-fast, fast-to-slow, slow-to-fast
and slow-to-slow transitions. Rename preserves the target. Nonfinal unlink
changes only link ownership; final unlink releases the inode and slow target
allocation and records explicit native deletion time without wiping payload.

Slow target bodies are journaled metadata. Replacement allocates any required
fresh slow block from the original audited-free set before releasing the old
block; slow-to-slow cannot recycle its original block. With no free blocks,
fast-to-fast and slow-to-fast can succeed when directory/inode prerequisites
permit, while operations needing fresh slow storage or parent-directory growth
refuse before writes. Fast creation needs a free inode and insertion room but
no target data block. Exact leased raw-inode and old slow-body guards accompany
typed semantic evidence through planning and both controller guard passes.
Full prospective ownership audit checks the resulting namespace and allocation.
OLD and NEW native home comparisons may mask only actual journal data blocks;
a fresh slow target is metadata and receives no regular-data OLD mask.

Focused compiled evidence is retained in `/tmp/partmgr-ext-symlink-public-v1.log`
(eight public consumer tests across 1/2/4 KiB),
`/tmp/partmgr-ext-symlink-audit-v1.log` (six independent audit tests, scoped to
1 KiB) and `/tmp/partmgr-ext-symlink-private-v2.log` (one private test exercising
nine forged-authority attacks and two valid controls). The public cases cover
all four storage transitions, exact aliases/native fields, unfollowed lifecycle,
packed-parent growth, genuine no-free distinctions, invalid inputs and source
guard failures with cold recovery obligations. The maintenance-audit retained
finding test also passes in `/tmp/partmgr-ext-symlink-retained-finding-v1.log`:
its previously blanket-unsupported symlink fixture now uses the explicitly
unadmitted short block-backed layout. The complete five-command host gate now
passes at `/data/cache/partmgr-maintenance-ext-symlink-checks-20261011-v5/result.json`,
with 365 unchanged source hashes independently matched to the live tree.
Earlier failed host attempts remain retained without acceptance. Native replay,
interruption and adversarial qualification are still required.

The integrated ignored `native_owned_ext3_ordered_symlink_cuts` gate uses
`PARTMGR_EXT_SYMLINK_CORPUS`, `PARTMGR_EXT_SYMLINK_EVIDENCE` and
`PARTMGR_GATE_SOURCE_ROOT`, with `ext-symlink-oracle.py` and independent
`ext-symlink-cuts-verify.py`. Its prepared corpus is input evidence, not writer
acceptance. Manifest-seven host checks pass for their exact source snapshot;
complete native replay/cut matrices, adversarial verifier controls and final
rehash remain required.

Repeated-sequence interruption matrices and broader E2 coverage remain open.
The earlier 27 same-owner snapshots establish successful successive operations,
rather than interruption coverage of those sequences. Wider hardlink policies,
qualification of the integrated symlink lifecycle, preallocation, modern write
profiles and metadata/ACL editing remain outside this curated surface. This is
offline modeled persistence evidence, without mounted-concurrency, kernel-crash
or hardware-durability qualification. E1 and the complete maintenance plan remain
incomplete.
