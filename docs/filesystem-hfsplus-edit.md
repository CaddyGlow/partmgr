# Bounded HFS+/HFSX fork editing

`fs_hfsplus::edit::HfsPlusEditSession` owns an exact bare filesystem `Storage`.
Opening requires a complete clean allocation/reference audit of the supported
nonjournaled HFS+ ASCII-fold or HFSX binary UTF-16 profile. The caller must exclude
other writers, including other handles to the same physical storage.

Supply explicit `HfsPlusEditLimits` for metadata pages, decoder restarts,
cumulative work, replacement bytes, native reader/audit work and external undo.
The decoder sees immutable copied metadata, never the mutable target. Preparation
and range planning revalidate those copies against the exclusively held target.

Use `plan_range(path, kind, offset, bytes, resources)` for DATA or resource-fork
bytes within existing EOF. A plan retains exact preimages and belongs to one
session generation. Commit consumes it; successful commits invalidate older
plans. A new plan can edit either fork afterward. This profile preserves all
filesystem metadata byte-for-byte, including timestamps and the write count.

`commit_range(plan, journal, binding, resources)` requires a fresh zeroed,
physically disjoint external journal with sufficient encoded body capacity.
`UndoBinding` is caller-verified volume, session generation and transaction
identity; the library does not discover physical aliasing or establish that
identity. Retain the binding, exact native path, fork kind, offset and length for
recovery. Commit durably publishes undo before dirtying both volume headers,
then flushes/verifies payload and completes structural audit before restoring
and flushing the clean bits. Durability depends on the Storage flush contract.

After an uncertain error, `needs_recovery()` is true and further plans reject.
Consume the stopped session with `into_storage()`. Call `recover_range` with
`HfsPlusRecoverySelection` and the original binding/selection. Recovery validates
that every saved payload patch belongs to exactly that audited fork range and
that both clean-state patches have exact framing. It restores and verifies old
payload while the headers remain dirty, audits the result, then publishes clean
state. Recovery can itself be interrupted and retried. Success grants no edit
session: reopen through complete owned preparation before further edits.

A committed journal verifies the new range; a prepared journal rolls back;
a rolled-back journal verifies the old range. A dirty target with no published
undo authority rejects. Keep uncertain target and journal bytes for diagnosis.

`resize(request, journal, binding, resources)` consumes the session. The request
specifies the final DATA or resource-fork length and an optional replacement
within that length. It copies retained logical bytes into audited free blocks,
zeroes growth and allocation tails, and applies the replacement. New allocation
must fit currently free space before releasing the old fork. Bitmap, overflow
tree, catalog fork and both header free counts are staged with exact preimages;
tree capacity and all resource limits are checked before mutation. Overflow-tree
header policy/reserved fields and its opaque user record remain exact. Other fork
bytes and old physical payload blocks are preserved. Success returns a freshly
audited session; failure returns owned storage and `UndoFailure`.

Retain the complete original `HfsPlusResizeRequest`, including replacement bytes,
and binding for `recover_resize`. Cold recovery validates external undo without
writing, reconstructs and fully audits the original metadata view from saved
preimages, regenerates the exact requested transition, and rejects mismatched
patches. Prepared transactions restore original allocation, metadata and bytes;
committed transactions verify the new state. Terminal retries perform no writes.
Reopen the returned storage before further edits after recovery.

`rename(HfsPlusRenameRequest, journal, binding, resources)` consumes the session
and changes the final native component within the same parent. It updates the
catalog key and matching thread within existing tree capacity, preserving raw
object bodies, directory children, catalog header/user records and other bytes.
Root, invalid names, collisions and insufficient capacity reject before writes.
Success returns a freshly audited session; failure retains storage through
`HfsPlusRenameFailure`. Retain the original path and new name for `recover_rename`,
which regenerates the exact transition from the audited saved original view
before restoring or verifying the selected terminal state.

Populated creation, native HFS+ journals, hardlink indirection and
populated attributes remain separate work.
The rename engine updates catalog object keys and their matching
threads within existing tree capacity, preserving raw object bodies and catalog
header/user records. Portable tests cover files and directories in both profiles,
every modeled commit and rollback write/barrier interruption with retained or
dropped target/journal writes, repeated cold recovery, and rejection of a
mismatched recovery name before writes. Native eight-case qualification now
covers successful and interrupted file/directory renames in both profiles,
independent fsck/namespace listings, complete file forks, exact raw object bodies
and directory child reachability. Evidence and immutable executable/source
bindings are in `/data/cache/partmgr-hfsplus-rename-native-v1` and its adjacent
`-fixed` directory. The native all-position gate also passes 552 resolved images
across both profiles and files/directories, all modeled commit and rollback
write/barrier positions, and four retained/dropped persistence combinations.
Every image passes native fsck, namespace and complete file-fork checks; bytes
outside the catalog remain exact. Its 3,037 artifact hashes and unchanged-source
fixed-executable bindings are in
`/data/cache/partmgr-hfsplus-rename-cuts-native-v1` and its adjacent `-fixed`
directory. The public consumer test covers both profiles, file/directory rename,
uncertain failure, mismatched-name zero-write rejection, terminal retries,
directory child lookup and reopening the returned storage.
The eight-case native gate has also been rerun through the public rename and
recovery APIs. Its fixed executable, unchanged-source checks and 57 artifact
bindings are retained under `/data/cache/partmgr-hfsplus-public-rename-native-v1`
and its adjacent `-fixed` directory.
Cross-parent move preparation validates the complete projected transition. Its projected audit checks
changed catalog keys/thread parent IDs and checked source/destination valence;
directory moves also account for native folder-count fields when enabled.
Portable preparation tests cover cross-parent file relocation in both profiles
and zero-write rejection of directory cycles and non-directory destinations.
The consuming commit/cold-recovery path retains the destination
parent in the semantic request. Portable cross-parent file tests cover successful
commit, interrupted catalog restoration, wrong-name and wrong-destination
zero-write rejection, terminal retries and every modeled commit/rollback
write/barrier cut with four retained/dropped persistence combinations in both
profiles. Native cross-parent file move qualification now passes all modeled
commit/rollback positions with four persistence combinations in both profiles.
Each resolved image passes native fsck, namespace/full DATA checks, explicit
empty-resource-fork checks and exact bytes outside the catalog. Source/executable
and artifact bindings are retained in
`/data/cache/partmgr-hfsplus-move-cuts-native-v1` and its adjacent `-fixed`
directory. Portable populated-directory moves now pass all modeled commit and
rollback cuts in both profiles using an independently constructed second parent.
Tests check retained child identity/reachability, disappearance of the old path,
valence and HFSX folder-count accounting through the complete projected audit.
Native populated-directory qualification also passes 276 resolved images in both
profiles, with native fsck, child namespace/full DATA, explicit empty resource
forks and exact bytes outside the catalog. Starting independently constructed
fixtures are normalized by native fsck only within explicitly checked header
status/last-mounted/write-count bytes, then independently checked before edits.
The failed fixture attempts are retained. Successful source/executable and 1,681
artifact bindings are under
`/data/cache/partmgr-hfsplus-directory-move-cuts-native-v4` and its adjacent
`-fixed` directory.

`move_entry(HfsPlusMoveRequest, journal, binding, resources)` consumes the session
and moves a file or populated directory to an existing destination directory;
an empty destination path selects root. It returns a freshly audited session or
`HfsPlusRenameFailure` retaining the target. Retain the original path, destination
and new name for `recover_move`. Root moves and directory cycles reject before
writes. The public consumer test covers files/directories and interrupted cold
recovery in both profiles, terminal retries and child reachability. Direct native
qualification through the public APIs passes all 1,104 resolved images: 552
rename, 276 cross-parent file move and 276 populated-directory move cases. Each
passes native fsck, expected namespaces, complete file/child DATA and resource
checks appropriate to its source profile, and exact bytes outside the catalog.
A single retained executable and unchanged-source guards cover all three runs;
6,651 output artifact hashes are retained across
`/data/cache/partmgr-hfsplus-public-rename-cuts-native-v1`,
`/data/cache/partmgr-hfsplus-public-file-move-cuts-native-v1` and
`/data/cache/partmgr-hfsplus-public-directory-move-cuts-native-v1`.
The common source/executable binding is in
`/data/cache/partmgr-hfsplus-public-namespace-cuts-native-v1-fixed`.
Empty-directory deletion preparation validates the complete projected transition. It removes the catalog
object/thread, checks and decrements parent valence/folder counts and mirrored
volume directory counts, then completely audits the projected volume without
writing. Portable tests cover both profiles, retained neighboring child lookup
and zero-write rejection of root/nonempty-directory deletion. Consuming
transaction and cold recovery pass
every modeled commit/rollback write/barrier cut with four retained/dropped
persistence combinations in both profiles. Recovery regenerates the deletion
from the audited saved original metadata; a different nonempty-directory request
rejects without target/journal writes or barriers. Native empty-directory deletion
passes every modeled commit and
rollback position with four persistence combinations in both profiles. Each
resolved image passes native fsck, expected presence/absence of the directory,
complete neighboring child DATA/empty-resource checks and exact bytes outside
the catalog and mirrored directory-count fields. The retained executable,
archived relevant source closure and unchanged-source checks are under
`/data/cache/partmgr-hfsplus-directory-delete-cuts-native-v1-fixed`; output
artifact bindings are in `/data/cache/partmgr-hfsplus-directory-delete-cuts-native-v1`.
File deletion preparation stages zero-length DATA and resource forks against
separately audited projected views, then removes the empty catalog object/thread.
Overlapping intermediate metadata changes are merged into exact original-to-final
preimages/replacements before the complete final allocation/reference audit.
Portable fragmented-fork tests cover overflow removal, both forks' allocation
release, file/free counts, preservation of all old physical payload bytes and
zero target writes in both profiles. File and empty-directory consuming commit
and cold recovery pass every modeled commit/rollback write/barrier cut with four
persistence combinations in both profiles, including mismatched-request rejection
before writes. Native fragmented DATA/resource deletion also passes all positions:
each resolved image passes fsck, expected namespace, file/free counts and surviving
child DATA/empty-resource checks; every byte outside catalog/overflow/bitmap and
the mirrored count fields remains exact, including old physical payload blocks.
Relevant archived sources, retained executable and unchanged-source checks are in
`/data/cache/partmgr-hfsplus-file-delete-cuts-native-v1-fixed`; output bindings are
in `/data/cache/partmgr-hfsplus-file-delete-cuts-native-v1`.

`delete_entry(HfsPlusDeleteRequest, journal, binding, resources)` consumes the
session and deletes a regular file or empty directory. It releases both forks and
overflow references together with catalog removal; old physical payload bytes
remain exact. Success returns a freshly audited session; failure retains storage
in `HfsPlusRenameFailure`. Retain the original native path for `recover_delete`.
The public consumer test covers files/directories in both profiles, successful
and interrupted commits, wrong-path zero-write rejection, terminal retries,
released physical payload preservation, free counts and reopening. The complete
portable deletion interruption matrix now runs through these public APIs.
Direct public native qualification passes all 872 resolved images: 356
empty-directory and 516 fragmented DATA/resource file deletion cases, covering
all modeled commit/rollback positions and four persistence combinations in both
profiles. A retained executable and unchanged relevant-source guards bind both
runs under `/data/cache/partmgr-hfsplus-public-delete-cuts-native-v1-fixed`.
The 5,282 output artifact bindings are in
`/data/cache/partmgr-hfsplus-public-directory-delete-cuts-native-v1` and
`/data/cache/partmgr-hfsplus-public-file-delete-cuts-native-v1`.
The frozen public-deletion source checkpoint
`/data/cache/partmgr-hfsplus-public-delete-source-v2-76_l5lyj` passed formatting,
strict all-target/all-feature locked Clippy, focused HFS authoring tests and the
full all-feature locked host suite. Adjacent `-sources.json` and `-checks.json`
bind the snapshot and command logs; this checkpoint predates creation work and
the subsequent shared catalog-commit refactor.
Creation preparation adds an empty file/directory and matching
thread using explicit native UID/GID/permissions/five dates, checks next-CNID
exhaustion/reuse, updates parent valence/folder counts and mirrored volume
file/directory/next-CNID fields, and completely audits the projected object.
Catalog rebuilding shares the existing capacity and header/user-preservation
helper. Portable tests cover both profiles and object kinds, typed metadata,
unchanged allocation, collision/invalid-name/non-directory-parent rejection and
zero preparation writes/refunds. Private consuming publication uses the shared
dirty-fenced undo transaction and renews the complete ownership proof. Cold
recovery reconstructs the original catalog and requires exact regeneration of
the saved patches from the requested parent/name/type/metadata. Both profiles
and object kinds pass committed cold validation, wrong-name zero-write rejection
and terminal zero-write behavior. Every creation commit write/barrier interruption
passes cold recovery in all four retained/dropped target/journal combinations:
the entire image equals the original or the nominal committed image, followed by
a fresh complete ownership proof and budget refunds. Every rollback write/barrier
interruption also passes a second cold restart across all four persistence
combinations: the original image is restored exactly and durably, with repeated
terminal recovery issuing no writes and all memory charges refunded. An initial
four-case native gate creates empty files/directories in both independently
checked builder profiles: fsck reports clean, TSK lists `DIR/Born`, and the
checker leaves image and source bytes unchanged. Its outputs are retained at
`/data/cache/partmgr-hfsplus-create-native-v1`; this initial run lacks a frozen
source/executable receipt and does not qualify interruption recovery or fork
preservation. Populated fork creation and complete native creation
qualification remained open at that checkpoint; public API evidence follows below.
The expanded eight-case run at `/data/cache/partmgr-hfsplus-create-native-v3`
also passes interrupted catalog-write cold rollback, exact original-image
restoration, full neighboring child DATA extraction, and explicit zero DATA and
resource-fork size checks for newly created files. The preceding v2 run retained
a test failure caused by expecting the wrong capitalization in TSK's resource
fork label; v3 checks its actual `Resource fork size` field. These runs still
require frozen source/executable binding and native all-position coverage.
The same eight-case native gate passed from the archived source snapshot
`/data/cache/partmgr-hfsplus-create-source-v1`, built into a separate target and
run from a retained executable. Its receipt at
`/data/cache/partmgr-hfsplus-create-native-v4-fixed/qualification.json` binds 54
executable/log/tool/adapter/source-image/output artifacts. All 2,356 snapshot
file hashes matched before and after execution. Native all-position coverage
was still open at that checkpoint. That snapshot's formatting, strict locked
Clippy, focused authoring tests and full all-feature locked host suite all passed;
the adjacent `-checks.json` binds command logs.
The initial native all-position gate at
`/data/cache/partmgr-hfsplus-create-cuts-native-v1` passed 872 resolved images in
48.16 seconds. Each commit/rollback outcome passed native fsck and complete
neighboring child DATA extraction; portable assertions check exact original or
nominal committed images, second-restart rollback and four persistence models.
This initial cut run has no frozen executable receipt; a frozen rerun is pending.
Native regular-file gates cover HFS+/HFSX commit and cold recovery, including
modeled torn writes/barriers and independent fsck/TSK full-payload checks. They
use the documented regular-file ioctl adapter and do not establish macOS or
hardware-device acceptance. Evidence is recorded in `docs/filesystem-progress.md`.

The frozen all-position creation rerun passed 872 resolved images. Its receipt
at `/data/cache/partmgr-hfsplus-create-cuts-native-v2-fixed/qualification.json`
binds 3,497 source-manifest/executable/tool/source-image/output artifacts, with
all snapshot hashes unchanged. The public `create_entry`/`recover_create` facade
is now implemented with `HfsPlusCreateRequest` and explicit
`HfsPlusCreateMetadata`; The public consumer test passes all eight profile/type/interruption cases,
including explicit UID/GID/mode/date round trips, wrong-type recovery rejection
without writes, exact rollback, terminal no-write recovery and session reopening.
The frozen public-facade all-position gate now passes all 872 resolved images.
Its receipt at
`/data/cache/partmgr-hfsplus-public-create-cuts-native-v1-fixed/qualification.json`
binds 3,497 artifacts and the archived public source snapshot. Both commit and
cold recovery call the public facade; each resolved image passes native fsck and
full neighboring child DATA extraction. Public-snapshot full required checks are
running separately. The historical private receipts retain their original scope.

Populated creation now has a private preparation primitive: against the audited
projected empty birth, stage DATA or resource-fork allocation, initialized
payload and resize metadata without writes. Both profiles pass complete
projected ownership checks and full payload comparison for each fork, with the
other fork empty and charges refunded. This is preparation only; composed atomic
publication of catalog birth plus both forks and matching recovery remain open.
The private populated-birth planner now composes catalog birth, DATA payload and
metadata, and resource payload and metadata against nested read-only projections.
It merges only overlapping/adjacent affected ranges into original-target
preimages and final replacements, with explicit memory/work ceilings. Both
profiles pass a complete audit of the merged final plan and exact comparison of
both populated forks, while the original target remains unchanged. Consuming
publication and cold semantic recovery of this populated plan remain open.
Private populated creation now also consumes the merged plan through the shared
undo transaction and renews the complete ownership proof. Cold recovery audits
the saved original view and exactly regenerates catalog birth plus both fork
payload/metadata changes; mismatched DATA rejects without writes. Both profiles
pass committed verification, interrupted merged-patch rollback to the exact
original image, terminal no-write recovery and budget refunds. The interruption
test selects an actual merged patch address because composition can join adjacent
catalog/payload ranges. All-position cuts, native populated creation, deferred
large inputs and a public populated-creation API remain open.
Populated creation's portable matrix now passes every commit and rollback
write/barrier cut on both profiles, with 10,003-byte DATA and 5,007-byte resource
forks spanning multiple allocations, all four persistence combinations and
second cold rollback restarts. Whole-image original/committed comparison and
terminal no-write/refund checks pass. Native populated coverage remains open.
The initial native populated-birth all-position gate passed in 26.10 seconds at
`/data/cache/partmgr-hfsplus-populated-create-cuts-native-v1`. Each resolved image
is checked with native fsck, TSK namespace listing and full neighboring DATA;
committed images additionally require exact 10,003-byte DATA and 5,007-byte
resource extraction for the new CNID. Terminal success establishes this initial run; source-bound qualification
remains pending.
The frozen populated-birth native rerun passed all 596 resolved images. Its
receipt at
`/data/cache/partmgr-hfsplus-populated-create-cuts-native-v2-fixed/qualification.json`
binds 3,002 executable/log/tool/adapter/source-image/output artifacts and the
2,356-file archived source manifest, checked unchanged before/after execution.
Required snapshot formatting/Clippy/focused/full host checks are now running in
a separate target. The public populated API and deferred input path remain open;
these bounded byte-slice tests do not satisfy streamed large-file creation.
Public bounded populated creation is implemented as
`create_file(HfsPlusCreateFileRequest, ...)` with `recover_create_file(...)`.
The request selects native parent/name, explicit/default metadata and complete
DATA/resource byte slices. The external consumer test passes both profiles with
success and interrupted merged-metadata recovery, wrong-payload zero-write
rejection, exact rollback, complete fork/EOF reads, explicit metadata round trips,
allocation counts, repeated terminal no-write recovery and session reopening.
Facade-bound native populated evidence and streamed input support remain open.
The populated creation interruption matrix now calls public `create_file` and
`recover_create_file`; every portable commit/rollback cut passes on both profiles
(18.76 seconds for this facade run). A separate frozen public snapshot at
`/data/cache/partmgr-hfsplus-public-populated-create-source-v1` is built and its
native all-position qualification is running. Earlier private receipts retain
their original scope and do not establish the public calls.
The frozen public populated-creation native gate passed all 596 resolved images.
`/data/cache/partmgr-hfsplus-public-populated-create-cuts-native-v1-fixed/qualification.json`
binds 3,002 artifacts; every artifact hash was independently reread afterward.
Both commit and cold recovery exercise public methods. Required frozen-snapshot
checks are now running in its separate target. Streaming creation remains open:
current byte-slice inputs and retained replacement patches require transaction
memory proportional to affected bytes within explicit caps, so these gates do
not establish bounded-memory large-file creation.
A streaming-undo prerequisite is staged independently in
`/data/cache/partmgr-undo-stream-draft-workspace/src/fs_undo_stream.rs`.
It validates the complete saved-body digest and range framing using 64 KiB
reads, retaining only a charged range index. A synthetic 16 MiB body /128 KiB
memory-budget test passed, including maximum read size and full refund checks.
This isolated draft neither changes production
recovery nor establishes streamed publication, semantic validation or replay.
The isolated streaming index also passes ten negative cases: a digest-valid late
overlap, overflowing length, trailing bytes, empty range, out-of-target range,
wrong digest, patch-count cap, causal read failure, memory cap and cancellation.
Every rejection refunds charges and its read-only journal forbids writes/flushes.
This strengthens decoding only; filesystem semantic validation and streamed
publication/replay remain unfinished.
The isolated streaming index now supplies read-only `Storage` views of saved
original/replacement ranges. Views use indexed overlap lookup, preserve target
bytes in gaps, read saved ranges in at most 64 KiB chunks, reject out-of-bounds
reads and refuse writes/flushes. Tests pass for original/replacement payloads at
chunk boundaries/EOF and for reads crossing multiple ranges with unchanged gaps,
within the same 128 KiB budget. No immutable `ReadAt` implementation is introduced.
Production HFS ownership audit integration and streamed replay remain open.
Both streamed saved-state views now pass the public HFS+/HFSX session's complete
ownership preparation after a real populated-creation undo transaction. Tests
compare every reconstructed image byte to the original or committed image in
charged 16 KiB chunks and refund both index and audit charges. The journal index
remains within 128 KiB; the separate native ownership proof uses its own 8 MiB
ceiling. This is isolated semantic-audit integration, not streamed publication
or write recovery. The draft reuses the existing independent fixture module.
The isolated streamed recovery prototype now restores saved originals in bounded
chunks, flushes and verifies every affected range, then writes/readbacks a durable
rollback marker. A complete old/new semantic validator runs before mutation.
The first test passes semantic rejection without writes/flushes, short writes,
exact restoration, causal/refund handling and terminal no-write retry within
256 KiB. This generic undo draft has no HFS dirty-fence integration or exhaustive
interruption qualification; production recovery remains unchanged.
The isolated streamed rollback now passes every restore/flush/terminal-marker
interruption with four target/journal persistence combinations and a second cold
restart. Two ranges include a 131,081-byte payload crossing 64 KiB boundaries;
997-byte short writes exercise repeated positional programs. Complete semantic
old/new image comparison precedes writes; every resolved target equals the
original exactly and durably, repeated terminal recovery performs no writes or
flushes, and charges refund within 256 KiB. HFS-specific fencing and streamed
publication are still separate unfinished work.

Both frozen populated-creation snapshots now have terminal passing formatting,
strict all-target/all-feature locked Clippy, focused authoring tests and full
all-feature locked host tests. The check receipts are adjacent to
`/data/cache/partmgr-hfsplus-populated-create-source-v1` and
`/data/cache/partmgr-hfsplus-public-populated-create-source-v1` (`-checks.json`).
These qualify the bounded slice profile; deferred streaming remains unfinished.

The isolated streamed recovery now also runs complete semantics against actual
restored/committed target storage after affected-range verification and before
terminal authority. A rejected actual-target audit leaves the Prepared journal
unchanged, reports target mutation and refunds all charges. All five streamed
prototype tests pass, including every rollback interruption and second restart.
Formatting and strict all-target/all-feature locked Clippy pass. Native HFS dirty
fencing and streamed publication remain open.

The isolated streamed publication prototype now emits the existing V1 body in
64 KiB chunks from caller-stable, exclusive/disjoint target and replacement
Storage sources. It flushes saved bytes, rereads complete framing and payloads,
compares both sources again, checks the saved digest and source geometry, then
publishes/flushes/readbacks Prepared authority. A 1,000,003-byte range passes with
160 KiB charged memory and 997-byte journal short writes; sources forbid writes
and flushes, saved journal bytes equal durable bytes, full streaming index proof
passes, pending Prepared reuse rejects without writes, and charges refund.
All six isolated prototype tests, formatting and strict Clippy pass. Publication
interruption qualification, source-failure matrices, structured uncertainty
reporting, HFS dirty fencing and production integration remain unfinished.

The isolated streamed publication matrix now passes every journal program/barrier
cut with retained/dropped unflushed journal state. Two ordered ranges include a
65,539-byte chunk-boundary case; 4,093-byte short writes exercise saved-body and
Prepared publication. Every cut leaves target bytes/durable bytes unchanged and
performs no target writes. Valid Prepared authority gets complete old/new image
proof and durable rollback; a second restart sees RolledBack. A retained torn
Prepared header rejects as InvalidData without writes instead of granting
recovery authority. All seven prototype tests pass within 256 KiB with refunds.
Source-failure matrices, structured uncertainty reporting and native HFS fencing
remain unfinished; production undo is unchanged.

The isolated streamed publication source-failure test now covers every replacement
read in saving/revalidation, changed bytes on either revalidation chunk, and
causal source geometry failure. All seven cases leave target/durable bytes
unchanged with zero target writes and no valid Prepared authority, including
separate retained/dropped pending-journal restarts. Causal failures remain Io;
changed bytes remain StalePlan; all charges refund within 160 KiB. The eight-test
prototype suite passes, and the corrected independent persistence branches pass
again. Formatting and strict Clippy pass. This verifies these source failures;
caller stability remains required and publication uncertainty reporting/native
HFS dirty fencing are still unfinished.

Isolated streamed publication now returns structured UndoFailure with the causal
error, failing stage, recovery requirement and target-mutation flag. Source and
body failures before Prepared publication report no new transaction recovery;
Prepared marker write/flush/readback failures conservatively require recovery,
and already-pending Prepared reuse also requires recovery. Publication always
reports no target mutation. The complete publication-cut matrix checks each
modeled Io failure's stage/uncertainty flags; source cases check Io/StalePlan and
no recovery/no target mutation. All eight tests, formatting and strict Clippy
pass. Reusing older terminal journals still needs its own uncertainty matrix;
production integration and HFS native dirty fencing remain unfinished.

Isolated terminal-journal reuse now proves its complete saved digest/framing,
volume binding and exact terminal target bytes before clearing authority. The
proof streams old/new bytes with charged 32 KiB buffers, dropping the index
before publication scratch allocation. A mismatched committed target rejects
StalePlan with zero journal writes; torn clear-header write and failed clear
barrier conservatively report recovery required and no target mutation. A clean
committed journal can then be republished as Prepared. All nine isolated tests,
formatting and strict Clippy pass. RolledBack reuse and exhaustive repeated-reuse
cuts remain to qualify; HFS dirty fencing/production integration remain open.

Terminal reuse tests now cover both Committed and genuinely streamed RolledBack
journals. Each checks mismatched-target rejection without journal writes, clean
republication, torn header-clear writes and failed clear barriers with separate
retained/dropped pending-journal restarts. Surviving old terminal authority,
empty cleared headers or InvalidData rejection are explicit outcomes; failures
report recovery uncertainty and no target mutation. All nine prototype tests,
formatting and strict Clippy pass. This is the terminal-clear boundary subset;
exhaustive repeated-reuse publication cuts and native HFS fencing remain open.

The terminal-reuse matrix now interrupts every publication program/barrier from
both Committed and RolledBack journals, with retained/dropped pending-journal
restarts. Every case preserves target/durable bytes exactly and refunds memory.
Surviving new Prepared authority passes full digest/framing index proof and
complete original/replacement image comparison. Old terminal, empty and torn
InvalidData outcomes stay explicit. Every modeled failure checks causal Io,
no target mutation, and recovery uncertainty at old-header clearing or new
Prepared publication. All nine prototype tests, formatting and strict Clippy
pass. This qualifies publication reuse only; native HFS fencing and streamed
commit/production integration remain unfinished.

The isolated streamed engine now also commits a Prepared journal. Complete saved
state semantics and exact live-original range checks precede writes; saved
replacement bytes stream through bounded scratch, then target flush/range
readback/actual-target semantic audit precede Committed publication. A 65,539-byte
range with 997-byte short writes passes exact durable replacement, stale-original
zero-write rejection, repeated terminal no-write verification and refunds within
256 KiB. RolledBack authority refuses commit. All ten prototype tests, formatting
and strict Clippy pass. Exhaustive commit interruption/native HFS fence gates
remain open; production undo and HFS edit methods are unchanged.

The isolated streamed commit now passes every target program/flush/Committed
marker interruption across four target/journal persistence combinations. Two
ranges include 131,081 bytes crossing scratch boundaries and 997-byte short
writes. Cold recovery resolves exact durable original or replacement according
to surviving authority, then a second restart and terminal retry perform no
writes/barriers. Complete old/new semantic image comparison and 256 KiB charge
refunds remain checked. All eleven prototype tests, formatting and strict Clippy
pass. This qualifies the generic isolated engine; HFS native dirty fencing,
request regeneration and production integration remain unfinished.

Streamed commit now explicitly refuses Empty authority as InvalidOperation
without callbacks/writes. Tests also reject RolledBack commit without callbacks
or writes. If the actual committed-target audit rejects after durable replacement,
the journal remains Prepared with no terminal writes, reports recovery required
and target mutation, and a cold streamed rollback restores exact durable originals.
All twelve prototype tests, formatting and strict Clippy pass. Production HFS
integration and native fencing remain unfinished.

The isolated streaming index now validates HFS native fence authority: primary
and alternate state bytes must each be isolated one-byte ranges with identical
saved clean old/new bytes, matching mirrored state and a live clean/dirty value
consistent with those saved bytes. Both real public populated-creation HFS+/HFSX
journals pass this prerequisite alongside complete saved-view ownership proofs.
All twelve prototype tests, formatting and strict Clippy pass. This decoder
check does not yet perform dirty fencing or deferred clean publication.

The isolated HFS fence-authority helper rejects nine malformed/foreign-state
cases without target or journal writes: missing/merged records, changed saved
replacement, saved dirty authority, unrelated live flags, mismatched mirrored
saved flags, invalid geometry, shifted alternate record and unrelated alternate
live state. Every case reports InvalidData and refunds charges. These focused
records exercise the helper after generic index proof; they do not replace body
digest/framing tests. All thirteen prototype tests, formatting and strict Clippy
pass. Actual native dirty/clean write sequencing remains unfinished.

Isolated HFS native fence write helpers now validate both preimages before writes,
program/flush/readback both dirty bytes, and require a caller's complete semantic
validator over a read-only clean-masked Storage view before programming/flushing/
reading back clean bytes. The helper test verifies durable dirty flags, rejected
audit with zero clean writes, exact complete masked image, durable final clean
bytes and refunds. All fourteen prototype tests, formatting and strict Clippy
pass. These helpers remain disconnected from streamed transaction orchestration;
real HFS ownership callback and native interruption qualification remain open.

The isolated engine now has HFS-fenced commit/recovery mode. It proves isolated
native-state authority before mutation, durably dirties both flags, skips clean
records during streamed payload writes/readback, audits actual target bytes
through a flags-only clean mask, then publishes/flushed/readbacks clean flags
before terminal authority. Real public populated-creation journals for both
HFS+/HFSX pass complete original/projected ownership audits, exact whole-image
streamed commit, then dirty-target streamed rollback to exact originals. Separate
audit budget remains 8 MiB; index/scratch remains bounded. All fourteen prototype
tests, formatting and strict Clippy pass. Native all-position fence qualification,
exact request regeneration and production/deferred-input integration remain open.

Real HFS+/HFSX populated-creation journals now pass every fenced streamed commit
program/barrier cut across four target/journal persistence combinations. Each
cold recovery performs complete saved original/projected ownership audits and
actual-target proof before clean publication, resolves exact durable whole-image
original or committed bytes, survives a second restart, and repeats terminal
recovery without programs/barriers. Short writes are 997 bytes; audit/index charges
refund. All fourteen prototype tests pass (5.76 seconds), with formatting and
strict Clippy passing. This is portable real-format evidence; native checker
qualification, interrupted rollback matrices, request regeneration and production
integration remain unfinished.

The real HFS+/HFSX fenced matrix now also interrupts every rollback program/
barrier, including dirty fence, restored payload, clean publication and terminal
marker, across all four persistence combinations. A subsequent cold recovery
with full ownership audits restores exact durable originals, then a second
restart/terminal retry performs no writes/barriers. Empty-journal HFS recovery
now rejects dirty/mismatched mirrored flags before semantic callbacks or writes;
clean empty recovery requires the complete actual-target validator. All fourteen
prototype tests pass (11.26 seconds), with formatting and strict Clippy passing.
Native checker qualification, exact request regeneration and production/deferred
input integration remain unfinished.

The isolated streaming index now compares an independently regenerated UndoPlan
against exact saved binding, geometry, body framing, ordered ranges and every
old/new byte using charged 64 KiB scratch. A 65,539-byte range passes; wrong
original, replacement, offset and transaction identity reject without target or
journal writes and refund charges. All fifteen prototype tests, formatting and
strict Clippy pass. The current comparator accepts retained bounded UndoPlan
patches; streamed HFS request regeneration must still supply bounded providers
for large payloads, and native/production integration remains unfinished.

Exact regeneration comparison now also accepts independently regenerated stable
Storage providers plus ordered range descriptors, avoiding retained payload
patches. It checks binding, complete range framing, provider geometry before/
after, and every saved old/new byte in bounded 64 KiB reads. The 1,000,003-byte
publication test passes provider comparison using a separate 128 KiB scratch
budget; wrong source bytes/offset reject without writes and refund charges.
The focused updated test, formatting and strict Clippy pass. HFS operation-specific
provider regeneration, native qualification and production integration remain open.

An isolated birth-payload Storage provider now maps deferred input onto borrowed
physical allocation descriptors. Reads preserve unchanged target gaps, overlay
file bytes in at most 64 KiB reads and zero every initialized allocation byte
beyond EOF, without retained payload buffers. Geometry/ordered nonoverlap/logical
coverage checks precede use; writes/flushes are refused. The focused test passes
fragmented allocation, exact zero tails/gaps and malformed allocation rejection;
formatting and strict Clippy pass. Descriptor ownership/free-space authority must
come from HFS allocation proof, and this provider still needs FileRead stability
binding, metadata composition and public creation integration.

The deferred birth provider now feeds streamed publication, exact regenerated
source comparison, streamed commit and rollback in one focused test. Fragmented
allocations preserve all gaps and zero EOF tails; complete old/new semantic image
comparison proves exact durable replacement and exact durable original recovery.
The transaction uses a 256 KiB ceiling and refunds all charges. The focused test,
formatting and strict Clippy pass. This integration uses externally supplied
allocation descriptors; HFS-owned allocation/metadata composition and FileRead
stability binding remain unfinished.

An isolated FileRead input adapter now requires explicit ImmutableSnapshot or
CallerGuaranteedStable admission and refuses ChangeDetectionOnly. It binds the
handle identity/length, checks them around every bounded read, handles short reads,
rejects premature EOF/oversized counts, and refuses writes/flushes. No Storage
input is promoted to immutable ReadAt. The focused test passes 3-byte short reads,
EOF behavior, both admitted stability declarations and unstable rejection;
formatting and strict Clippy pass. The declaration remains caller authority,
not a snapshot inferred from identity checks. Mutation/error matrices and HFS
allocation/metadata integration remain unfinished.

The isolated FileRead adapter now passes five explicit failure cases: zero reads
before EOF, oversized counts, causal read Io, changed identity and changed length
on the first deferred read. Premature/invalid counts reject UnexpectedEof; nested
causal Error retains Io and the original source diagnostic; observed mutation
retains StalePlan. Each stops after one read and refunds all charges. Both adapter
tests, formatting and strict Clippy pass. These identity checks do not establish
snapshot isolation; HFS-owned allocation/metadata integration remains unfinished.

The isolated HFS planner now exposes a cfg(test) birth-layout prerequisite using
its existing complete ownership proof/free-range allocator and metadata staging.
It retains only charged physical/logical allocation descriptors plus native
metadata patches, requires an empty original fork, and revalidates before return.
Both DATA/resource and HFS+/HFSX preparation cases prove metadata byte-for-byte
identical to bounded payload staging and matching total initialized allocation.
All five isolated creation tests pass (three explicit native gates ignored), with
formatting and strict Clippy passing. Production is unchanged; deferred payload
composition and public streaming creation remain unfinished.

The isolated HFS birth-layout descriptors now feed the deferred payload provider
and native metadata projection together. Both forks/profiles pass complete
ownership preparation, and every projected image byte matches the existing
bounded payload/metadata image in charged 4 KiB comparisons. The deferred source
receives no writes; preparation remains read-only. The focused preparation test,
formatting and strict Clippy pass. This composition is isolated/cfg(test); whole
transaction range composition, deferred public creation and native qualification
remain unfinished.

An isolated charged descriptor composer now unions overlapping/adjacent payload
and metadata ranges without copying payload bytes or absorbing isolated native
state markers. It validates checked target bounds, state overlap, final patch/body
caps and cancellation; scratch/output allocations are reserved before allocation.
The focused test passes overlap/adjacency, preserved state isolation, invalid
state overlap/out-of-bounds/patch-cap rejection and refunds. Formatting and strict
Clippy pass. Whole HFS creation transaction/provider composition remains open.

The isolated real HFS creation composition now publishes catalog birth, deferred
single-fork payload, native metadata and isolated state descriptors as one V1
streamed transaction. Both DATA/resource selections on HFS+/HFSX pass complete
saved-state/actual-target ownership audits, fenced streamed commit with every
image byte equal to bounded creation, and exact durable rollback to originals.
Descriptor allocations are charged; payload remains a deferred provider. The
focused test passes, with formatting and strict Clippy passing. The isolated test
is now named typed_creation_preparation_and_streamed_fork_transactions to reflect
its additional transaction scope. Two-fork simultaneous deferred composition,
large-file controls, native qualification and production integration remain open.

The isolated creation transaction now composes both deferred forks together.
Second-fork allocation uses the complete audited first-fork projection; final
catalog/bitmap/free-count metadata overrides staged earlier values. Both fork
orders on HFS+/HFSX pass complete final ownership proof, fenced streamed commit
with every byte equal to two-stage bounded creation, exact durable rollback and
zero writes to either deferred source. The focused test, formatting and strict
Clippy pass. Large-file budget controls, real deferred FileRead composition,
request regeneration/native qualification and production integration remain open.

Both deferred forks in the isolated real creation transaction now use FileRead
handles through explicit stable-input adapters. Three-byte short reads pass all
allocation/metadata projection, complete ownership audits, V1 publication,
fenced commit and exact durable rollback in both fork orders/profiles. One input
declares caller-stable backing, the other a retained immutable fixture; neither
is promoted from mutable Storage to immutable ReadAt. The focused test, formatting
and strict Clippy pass. Large-file controls, operation-specific cold regeneration,
native qualification and production integration remain unfinished.

A generated 8 MiB+3-byte deferred FileRead source now passes fragmented birth
provider publication, complete saved-provider comparison and streamed commit
within a 256 KiB transaction budget. Two allocation ranges preserve gaps and
zero block tails; 997-byte source reads/target and journal writes exercise bounded
loops. Complete old/new image validation checks every byte of a 12 MiB target,
exact durability and refunds. Caller-owned Model target/journal fixtures are
outside transaction charges; no replacement file buffer is retained. The focused
test passes (0.66 seconds), with formatting and strict Clippy passing. This is a
generic payload/undo large-file control, not full large-HFS allocation/native proof.

The composed two-fork HFS creation test now validates published Prepared authority
through complete digest/framing index proof and exact generated original/final
provider comparison before any target program. Every saved old/new byte and
range descriptor must match the composition; verification performs no writes.
Both fork orders/profiles pass the focused test, formatting and strict Clippy.
This is comparison against the prepared composition; independently rebuilding
that composition from a cold recovery request remains unfinished.

Cold saved-view validation now independently rebuilds catalog birth and both
fork allocations/metadata from the streamed original view and original request.
Both short-read FileRead inputs supply payloads again; regenerated complete
ownership proof, exact saved-provider comparison and every projected image byte
match before rollback receives write authority. Both fork orders/profiles pass
without validation writes. The focused test, formatting and strict Clippy pass.
The test still compares against the initially retained descriptor union; fully
cold descriptor regeneration/public recovery and native qualification remain open.

Cold two-fork regeneration now also reconstructs its charged descriptor union
from regenerated catalog birth, both fork allocation/metadata sets and native
state positions derived from saved-original geometry. Exact published-source
comparison uses this new union rather than retained transaction ranges/layouts.
Every old/new saved byte and descriptor matches without writes; both fork orders/
profiles pass the focused test, formatting and strict Clippy. The implementation
remains an isolated test composition; public cold recovery, native qualification
and large-HFS memory proof remain unfinished.

An isolated reusable with_streamed_birth planner callback now owns catalog birth,
DATA-first/resource-second audited allocation, deferred payload/native metadata
composition and charged descriptor union. It revalidates the original target
before exposing a complete audited final Storage projection/ranges to its consumer.
Cold saved-original reconstruction uses this method and matches every saved byte/
descriptor for both profiles. The focused test, formatting and strict Clippy pass.
The helper remains cfg(test); bounded input/public facade integration, native
qualification and full large-HFS proof remain unfinished.

An isolated reusable cold streamed-birth request validator now opens complete
saved original/replacement ownership proofs, regenerates DATA-first/resource
creation through with_streamed_birth and compares independently reconstructed
ranges/providers against every saved byte. Exact saved-source comparison accepts
terminal as well as Prepared authority, permitting terminal request verification
without writes. Both profiles pass correct-request validation and wrong-name
rejection with unchanged target/journal write counts. The focused test, formatting
and strict Clippy pass. Public owned commit/recovery handoff, native qualification
and full large-HFS memory proof remain unfinished.

The reusable cold validator now passes exact request checks on Committed,
Prepared and RolledBack journals for both profiles. Wrong UID metadata and a
same-length wrong DATA provider reject before writes, alongside wrong-name
rejection. Every terminal/request verification keeps target/journal write counts
unchanged and refunds charges. The focused test, formatting and strict Clippy
pass. Public owned handoff, native qualification and large-HFS memory proof
remain unfinished.
# Isolated streamed owned recovery checkpoint

The draft in `/data/cache/partmgr-undo-stream-draft-workspace` now has an
owned streamed-birth recovery handoff. It regenerates the exact requested
catalog metadata and both fork inputs against saved old/new views before
allowing any recovery write. Failure returns the caller's actual storage;
success reopens and fully audits the recovered storage before transferring
the fresh proof into an owned session.

The focused `typed_creation_preparation_and_streamed_fork_transactions` test
passes for HFS+ and HFSX. It rejects a wrong request with unchanged target and
journal write counts, recovers the correct request to the exact durable
original image, and checks the returned rollback status. Draft formatting
and strict all-target/all-feature Clippy also pass. These checks do not
qualify native interoperability or promote a public streamed API. Native
source-bound qualification remains open.

The isolated draft also implements the owned streamed commit facade. It
publishes through the deferred birth provider, regenerates and validates the
exact published request before target writes, and performs a fresh complete
audit before returning the owned session. The same focused HFS+/HFSX test
checks terminal-journal reuse, exact durable equivalence to the independently
staged bounded two-fork transaction, and invalid-name preparation returning
the original storage without any target or journal writes. This remains a
test-only draft; it does not extend the public production profile.

The draft commit handoff also rejects a session already marked uncertain
before preparation or journal access, returning its storage with recovery
required. The focused test checks that both stores' write counts remain
unchanged. The full isolated host suite is being checked separately; its log
is `/data/cache/partmgr-streamed-owned-fullhost-v1.log` and is not a native
qualification receipt.
