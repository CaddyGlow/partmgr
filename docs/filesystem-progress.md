# Filesystem plan implementation progress

This is a partial implementation record, not completion of FILESYSTEM_PLAN.md.
The intended family/operation scope is unchanged. Work uses published crates.io
virtdisk 0.2.0; source/build APIs added here require a future partmgr release.

## Current implementation work

NTFS whole-volume allocation/reference audit and facade integration are complete
for the supported base-record profile. Eight audit tests, ten facade tests,
fourteen fuzz smoke tests and native audit/namespace/optical gates pass.
FAT extension/truncation passed 546 native resize cases and 159 range regressions.
Deterministic classic ext2 authoring now
passes four portable tests and eight e2fsprogs native images, with exact payload,
hard-link and native byte-name checks. The XFS baseline reader, audit, tree source and facade route are implemented;
its final xfsprogs native gate passed, including independently recovered payloads, native names, sparse/unwritten ranges and unchanged framing.
The shared FAT decoder supports exclusive
Storage inspection without a mutable ReadAt adapter; its audit now validates
reserved entry-zero media and entry-one encoding independently of dirty flags.
The common read facade has checked dispatch, explicit audit policy/evidence and
source-length/cancellation guards retained through deferred EOF reads. External
undo now supports caller-ordered write/flush/readback stages with an unchanged
sorted v1 journal and recovery path; eight portable undo tests pass, including
every staged write/barrier cut and verification-before-reference invariants. Root
profile tests now cover six current engines, including XFS. New work requires a fresh final
check and evidence freeze; older full-check/fuzz receipts below bind the
preceding verified state and do not automatically cover subsequent additions.

## Implemented and checked

- Common lossless names/identities/metadata, explicit per-operation capabilities,
  structured errors, concurrent shared budgets, cancellation, retained inventory
  reservations, positional streams and bounded whole-file convenience access.
- Owned bounded mutable Storage sessions, explicit unknown sector facts,
  read-after-write, bounds-before-mutation and sticky mutation/flush uncertainty;
  separately bounded immutable reads retain backend context and budgets.
- Validated indexed uncompressed extent handles: no construction-time payload
  access, coalesced adjacent source calls, holes/unwritten zero semantics,
  caller buffers and concurrently shared immutable handles.
- FAT12/16/32 BPB geometry, bounded FAT chains, mirror agreement and active FAT
  profiles; bounded native directory enumeration, exact lookup, strict VFAT
  slot/checksum/ordinal/padding decoding and namespace-scoped stream identities.
- Common FAT capture inventory with bounded full-tree traversal, directory
  cycle/alias rejection, native names, opaque native timestamp fields and deferred
  positional streams. This is not a whole-volume allocation ownership audit.
- Deterministic FAT12/16/32 new-output builder: nested directories, exact UTF-16
  VFAT names and collision-safe deterministic short aliases under the documented
  ASCII comparison profile, streamed payload/free-space initialization, mirrored FATs,
  FAT32 FSInfo/backups, one flush, complete readback/digest verification and
  explicit post-mutation failure/cancellation outcomes.
- Independent native FAT reader/authoring harness; exact tool commands/versions,
  native fsck nonrepair acceptance, mtools extraction hashes, VFAT long-name
  comparison, repeated deterministic image hashes and unchanged inspection.
- FAT fuzz target covers geometry, bounded namespace/chain traversal and direct
  reads and whole-volume ownership auditing, with independently assembled packed
  FAT12 seeds. The ext target uses an independent classic ext2 fixture. Smoke fuzzing is not
  exhaustive malformed-input or security qualification.
- FAT ownership/status audit: cross-links, cycles, lost allocation, length/mirror
  findings and bounded free-data ranges; unsupported diagnostic classes remain
  documented in `filesystem-fat-audit.md`.
- Clean classic ext2 readers with indexed indirect/sparse maps, allocated-bit and
  metadata-overlap validation; bounded tree source retains byte names, UID/GID,
  modes, native flags, opaque native timestamps, file hard-link identities and
  exact inline/block-backed symlink targets without following them.
- Whole-volume ext2 bitmap, metadata, complete classic-map and namespace/reference
  auditing, with clean-only free ranges and independently generated/native fixtures.
- Direct-read benchmark harness with paired filesystem/backend workloads, explicit
  numeric work/reservation/RSS gates and descriptive CPU/latency measurements.
  A bounded metadata cache reduced ext2 setup backend reads from 179,117 to 80
  on the recorded 16 MiB fixture; payload hashes and retained-map charge matched.
- Content-only common-tree FAT copy preflight, retained deferred sources, explicit
  metadata/name outcomes and staged emission. The CLI reopens/audits output,
  publishes without overwriting and reports directory-sync durability separately.
- Unpublished optical integration: bounded retained ISO/UDF sources, raw and
  compressed-QCOW2 reads, deferred common file handles, staged TreeSource writers,
  UDF named/root/system streams, explicit ContentOnly metadata policy, native
  parent topology, classified sparse maps and an optical tree adapter.
  Native ISO/UDF-to-FAT content-only copies pass; preservation mappings remain required.
- Clean single-FAT exFAT revision 1.00 boot checks, allocation/upcase validation,
  exact UTF-16 namespace and indexed chained/contiguous file reads. Valid-data
  tails return zeros without backing reads. A bounded tree source and content-only
  FAT copy route and full bounded ownership/state audit are implemented. Clean
  audit is now required before CLI capture. Deterministic exFAT nested authoring
  and common-tree content-only staged capture now have independent fsck/TSK gates.
- NTFS 3.1 clean-marker reader: checked boot/MFT/USA/attributes and indexed
  resident/nonresident unnamed data, sparse/unwritten zeros, native UTF-16 names
  and source/record-sequence identities. Real INDEX_ROOT/ALLOCATION/bitmap tree
  traversal and explicit namespace policies are implemented; system exclusions
  require opt-in and retained exact reports. Native directories match TSK;
  direct user-namespace ISO/UDF capture matches 7z. The complete supported-profile
  audit includes all raw attribute allocations beyond logical EOF, MFT/volume
  bitmaps, native directory references, system streams, bad clusters and mirrors.
  It exposes free ranges only after complete finding-free accounting; this is
  not journal replay or system-stream capture support.
- External undo v1 saves bounded before/after patches to a disjoint medium before
  target mutation, verifies flushes and supports restartable rollback. Exhaustive
  modeled write/barrier cuts and native FAT16 existing-payload cases pass; a
  general filesystem editor is not thereby implemented. The owned FAT range editor
  now integrates this journal with same-session complete inspection, scoped file
  maps, generation invalidation and reinspection after recovery. Native FAT12/16/32
  FileStorage failure-cut gates pass; allocation/name/length edits remain open.
- The owned ImageWriter session is now part of `fs_storage`; its raw/QCOW2
  consumer tests use published virtdisk 0.2.0, with no virtdisk override.

Root repository formatting, locked all-target/all-feature Clippy with warnings
denied and locked all-feature tests pass with the isolated build target
`/data/cache/partmgr-filesystem-target`. Isolation avoids collisions in the
machine-wide shared build directory; it changes no dependency resolution.
The instrumented nine-target smoke receipt is
`/data/cache/partmgr-filesystem-fuzz-nine-20261008/summary.json`: 1001 iterations
each for partitions, guid, layouts, payload, fat, ext, exfat, ntfs and undo, zero crashes or
timeouts. All recorded source hashes matched after completion. This bounded
smoke campaign does not establish exhaustive malformed-input qualification.

Native evidence for nine reader/authoring profiles, including nested trees:
`/data/cache/partmgr-filesystem-native-evidence/20261007T203552Z-2/evidence.json`.
Native bounded FAT copy evidence:
`/data/cache/partmgr-filesystem-native-copy-evidence/20261007T221017Z-2/evidence.json`.
Native four-sector-size exFAT boot evidence:
`/data/cache/partmgr-exfat-boot-20261007-b/evidence.json`.
Scope is conventional 512-byte-sector fixtures, not every FAT variant, geometry,
fragmentation pattern, corruption mode or physical backend. Separate generated
EFI GPT/MBR runtime evidence is recorded in
`/data/cache/partmgr-framework-firmware-20261007-b/receipt.json` and the independent
native-FAT regression receipt; see `filesystem-firmware.md` for its exact scope.
Every receipt binds its own source/profile hashes; later edits need new evidence.

## Additional profile receipts

These receipts each bind their own exact source and executable hashes. Ongoing
changes require a new receipt before claiming acceptance for the updated source.

- Deterministic exFAT builder: `/data/cache/partmgr-exfat-builder-20261008/exfat-direct-builder-tree-v1.txt`; native32/64MiB repeated images, fsck/fls/icat. Independent complete Unicode case comparison remains a documented gap.
- Direct common-tree exFAT output: `/data/cache/partmgr-exfat-output-copy-evidence/20261007T223503Z-2/evidence.json`; FAT/ext2/exFAT nonzero source regions, deterministic outputs, exact names/hashes, VDL zero tails, early no-clobber and lost-allocation rejection.
- NTFS native indexes: `/data/cache/partmgr-ntfs-tree-native-20261008-frozen/receipt.txt`;96 native records checked against TSK and explicit complete/user namespace policies.
- Direct NTFS user-namespace optical capture: `/data/cache/partmgr-ntfs-optical-native-20261008-frozen/receipt.txt`;32 nonresident files compared through TSK and7z, exact reserved-root omission report, preservation rejection. NTFS global audit changes need reader/index regression evidence to be refreshed.
- Owned FAT existing-length range editor: `/data/cache/partmgr-fat-edit-native-20261008-reserved-final/receipt.txt`;159 cases across FAT12/16/32, including every52 write/barrier cuts per family, native fsck/mcopy and exact unaffected container/metadata bytes. Extension/truncation and namespace mutation remain separate acceptance work.
- Common read facade: six checked profile/contract tests also passed from a self-contained packaged crate snapshot. The fresh full package gate is in `scripts/filesystem-package-check.py`; a clean freeze is still required.

## Dependency work handed off

`../mkiso-rs/FILESYSTEM_REFACTOR_PLAN.md` contains the audited R1-R3 contract,
compatibility/feature requirements, streaming/metadata gates and release ledger.
It is a handoff for the user's separate agent. UDF has not been duplicated here.
The positional reader/deferred writer APIs now pass local integration against the
published libmkiso 0.1.4, including native extraction, classified extents, native topology and the optical-to-FAT pipeline. The new partmgr APIs need a release. The sibling
`FILESYSTEM_V012_FOLLOWUP_PLAN.md` requests classified sparse extents and optional
retained inventory leases; `FILESYSTEM_TOPOLOGY_FOLLOWUP_PLAN.md` requests native
parent/leaf topology for optical TreeSource construction without display-path loss.
The actual `ImageWriter` R4 bridge now lives in `fs_storage` and passes raw/QCOW2
consumer tests and independent conversion using published virtdisk 0.2.0. Only
partmgr's new API checkout requires a development override. The plain portable
wasm gate now fails on that release's unconditional getrandom dependency; a
flags-only diagnostic build passes but does not close the gate. The sibling
`virtdisk/FILESYSTEM_V020_PORTABLE_FOLLOWUP_PLAN.md` records the demonstrated
regression and narrow target/feature refactoring request. Wider backend and
performance gates remain open.

## Remaining work by milestone

| Milestone | Remaining acceptance work |
| --- | --- |
| 0 | Finalize versioned source/sink, flash and container contracts; pin remaining family specs/oracles and actual release API versions; executable build/edit/copy/failure examples across profiles |
| 1 | Portable virtdisk compatibility and wider backend/failure profiles; controlled raw/container performance baselines, write/commit workloads and per-profile timing/regression release thresholds |
| 2 | Remaining FAT status/metadata/OEM comparison profiles; exFAT Unicode mounted comparison and broader geometry gates; optical preservation/partmgr release gates; El Torito EFI runtime and nonbaseline geometry evidence |
| 3 | Broader ext features, NTFS complete system-stream capture and advanced attribute/allocation profiles, and XFS, HFS/HFS+/HFSX, APFS, JFS and JFFS2 readers, audits, tree adapters and independent corpora |
| 4 | FAT namespace and broader allocation profiles, exFAT/ext2 recoverable existing-volume edits using external recovery, additional authoring profiles and interruption/native evidence |
| 5 | Format-specific native journal/COW writable engines, replay/publication and allocation/reference invariants for each operation |
| 6 | Flash mutation/GC/backends, transactional/advanced/encrypted/compressed/snapshot/external-device profiles, explicit resizing and their evidence |

Complete versions of all six pipeline flows, layer capability reports, faithful
preservation policies, multi-stage recovery, exclusive audited discard and complete
release/performance evidence remain required. Implemented content-only copies and
the generated EFI runtime gate close only their documented profile requirements.

Current native receipts also include:

- exFAT ownership audit: `/data/cache/partmgr-exfat-audit-vdisk02-20261008/exfat-audit-basic-v1.txt`.
- Audited bounded exFAT capture: `/data/cache/partmgr-exfat-copy-native-evidence/20261007T220823Z-2/evidence.json`.
- NTFS registry reader: `/data/cache/partmgr-ntfs-native-vdisk02-20261008/receipt.txt`.
- External undo: `/data/cache/partmgr-undo-native-vdisk02-20261008/fat16-external-undo-existing-payload-v1.txt`.
- Registry ImageWriter bridge: `/data/cache/partmgr-writer-bridge-registry-20261008/writer-bridge-mV5nUM/evidence.txt`.

## Current allocation and package evidence

- NTFS complete base-record audit: `/data/cache/partmgr-ntfs-audit-native-20261008-final/receipt.txt`;2235allocated/owned clusters,14148free clusters,67allocated records,263attributes and no findings.
- NTFS namespace and capture regressions after audit changes: `/data/cache/partmgr-ntfs-tree-native-20261008-audit-frozen/receipt.txt` and `/data/cache/partmgr-ntfs-optical-native-20261008-audit-frozen/receipt.txt`.
- Direct classic ext2 builder: `/data/cache/partmgr-ext-builder-evidence/classic-ext2-direct-builder-v1.txt`;eight e2fsck/debugfs validated deterministic images, exact hardlinks, payloads and native byte names.
- Self-contained package snapshot: `/data/cache/partmgr-package-gate-ejoaoxvr/evidence.json`;packaged fmt, all-target/all-feature locked Clippy and all-feature locked host tests passed with crates.io virtdisk0.2.0. This is neither publication nor portable/native/firmware evidence.

- FAT resize final: `/data/cache/partmgr-fat-resize-native-20261008-final/`;546 native cases across FAT12/16/32 extend, truncate, zero and empty-file extension. Range regression: `/data/cache/partmgr-fat-range-native-20261008-resize-final/receipt.txt`;159 cases. Missing-tool/destination controls: `/data/cache/partmgr-fat-resize-final-negative-z54rsz_8/control.json`.
- Instrumented bounded fuzz snapshot: `/data/cache/partmgr-filesystem-fuzz-ntfs-audit-resize-20261008/summary.json`;all nine targets1002iterations each, zero crashes/timeouts, every recorded source hash verified current at completion. Later engine changes require new receipts.

- Owned raw/QCOW2 filesystem edits: two storage-consumer tests plus independent qemu-img check/conversion pass for replacement/extension/truncation. Whole-disk framing and reviewed-patch equality, retained writer/journal locks and reopened ownership audit are verified. Receipt: `/data/cache/partmgr-fat-container-edit-20261008/fat-qcow2-m67MNE/evidence.txt`;negative controls: `/data/cache/partmgr-fat-container-negative-j_k6xnfp/control.json`. This is container interoperability, not native filesystem or physical failure evidence.

## Flash and XFS integration work

The declared `FlashStorage` contract and owned logical NOR emulator are implemented
in `fs_flash`. Six tests pass, including48 modeled program/erase write cuts;
preflight enforces transitions, alignment, bounds, bad-block exclusions and limits.
JFFS2 decoding and offline authoring subsequently passed their separate gates. Physical NAND/OOB/ECC, append/GC and hardware behavior remain open.
The XFS v5 baseline now dispatches through ReadImage with eight facade tests;
its independent seed reaches complete auditing and sparse/hardlink reads in a
new XFS, flash and JFFS2 fuzz targets. Fourteen fuzz smoke tests pass across twelve targets. New package/native/fuzz
receipts must bind this later source state; earlier snapshot receipts are historical.

The exFAT owned replacement/resize editor passed six portable tests and the exact-source native gate `/data/cache/partmgr-exfat-edit-native-20261008-frozen-v4/receipt.txt`. Commit and rollback retain dirty state until verification and complete audit succeed. Namespace editing subsequently passed its separate gate below.

Raw and QCOW2 exFAT editor integration now passes replacement across VDL, zero extension, truncation, exact reviewed-patch whole-disk comparison, writer/journal lock retention, stale-handle rejection and reopened complete audit. Root formatting, all-target/all-feature locked Clippy and all-feature locked tests pass for the checked development state; this is not a frozen package or instrumented campaign receipt.

JFFS2 logical NOR reader/audit/tree native gate passed at `/data/cache/partmgr-jffs2-evidence-final-2/jffs2-logical-nor-none-v1.txt`. Common dispatch requires explicit geometry and byte order and always audits its inventory. Ten facade tests and fourteen fuzz smoke tests across twelve targets pass; fresh packaged/instrumented receipts remain required. Offline JFFS2 authoring is the next agent task.

## JFFS2 facade and isolated verification snapshot

The captured source `/data/cache/partmgr-fuzz-jffs2-source-jyc7nvyg` passed the
packaged-source fmt/all-target-all-feature locked Clippy/all-feature locked test
gates: `/data/cache/partmgr-package-jffs2-jyc7nvyg/evidence.json`.
All twelve instrumented targets completed1002 iterations each with zero crashes
and timeouts: `/data/cache/partmgr-fuzz-jffs2-source-jyc7nvyg/campaign-bfd-dev/summary.json`.
Every recorded source hash matches the retained snapshot; the separate
`source-audit.json` records that check and the native-library recipe. Initial
campaign setup failures from missing bfd.h are retained alongside the successful
run. These are snapshot receipts, not proof for later FAT/exFAT namespace or
JFFS2 builder additions. The full plan remains active.

FAT namespace create/rename/move/delete is frozen after8portable tests,13existing editor regressions and904native cases (27normal+877 faults) acrossFAT12/16/32. Receipt `/data/cache/partmgr-fat-namespace-native-20261008-final/receipt.txt`, source verification.json and negative-control control.json bind that gate. Native cuts cover continuing-owner recovery; restart persistence models remain deterministic-test evidence.

Classic ext2 common-tree capture is implemented with native byte names, explicit UTF16 conversion, caller metadata defaults and preserved regular hardlinks. Four portable tests and independent16MiB e2fsck/debugfs gate pass: `/data/cache/partmgr-ext-copy-native-20261008-final/ext2-copy-V1PUei/receipt.txt`. Ext2 recoverable editing is the next agent task and remains required. Prior isolated package/fuzz receipts predate this addition.

ExFAT namespace creation/rename/move/deletion is frozen with five portable
namespace tests and native51-payload/root+subdirectory-growth evidence at
`/data/cache/partmgr-exfat-namespace-native-20261008-frozen-v3/receipt.txt`.
Existing replacement/resize gate was refreshed at
`/data/cache/partmgr-exfat-edit-native-20261008-namespace-refreeze-v5/receipt.txt`.
JFFS2 offline authoring passed four portable tests and eight independently
validated native images at
`/data/cache/partmgr-jffs2-builder-evidence-final-2/jffs2-direct-tree-builder-v1.txt`.

The standalone ext2 capture example and native stage/publication gate passed:
`/data/cache/partmgr-native-ext-capture-20261008-final/ext2-capture-r6ats8l5/evidence.json`.
It verifies nonzero-offset raw views, exact native bytes/hardlinks/payloads,
existing-destination refusal and source-profile rejection before destination
creation. The shared Undo v1 codec now supports internal semantic fence validation
without changing public recovery or encoding; two new invariant tests and eight
existing undo tests pass. Agents continue ext2 mutation/recovery, HFS+/HFSX reader
expansion and declared NOR append/GC. These additions require fresh snapshot
package/fuzz receipts before release; the whole plan remains incomplete.

Latest isolated namespace/builder/copy/Undo snapshot:
`/data/cache/partmgr-namespace-build-source-ytp116fi`. Packaged fmt/all-target-all-feature
locked Clippy/all-feature locked tests passed at
`/data/cache/partmgr-package-namespace-build-ytp116fi/evidence.json`.
All12instrumented targets completed1002iterations each with zero crashes/timeouts:
`/data/cache/partmgr-namespace-build-source-ytp116fi/campaign/summary.json`.
The adjacent source-audit.json confirms every recorded snapshot source hash.
This snapshot includes FAT/exFAT namespace editing, JFFS2 offline authoring,
classic ext2 common-tree capture and CLI, the shared borrowed ext decoder checkpoint
and internal Undo semantic validator. Subsequent ext2 mutation, HFS reader and
flash append/GC work remains separate acceptance work and is not covered by
these receipts. Instrumented targets cover their documented harness operations;
the campaign does not substitute for native namespace fault/recovery gates.

The exFAT mutable directory inventory now binds every public entry identity to the
current owner generation, including nested directories after a committed transaction.
The ordinary namespace regression and native root/BOX inventories enforce source and
generation consistency. Refreshed native receipts are
`/data/cache/partmgr-exfat-namespace-native-20261008-generation-v4/receipt.txt`
and `/data/cache/partmgr-exfat-edit-native-20261008-generation-v6/receipt.txt`.
Both passed independent exfatprogs/TSK validation; earlier receipts remain historical
evidence for their captured sources. The namespace gate retains 51 matching payloads.

The common immutable facade now exposes explicit HFS+/HFSX opening and bare
volume-header signature candidates. Inventory always requires the complete
supported ownership audit, including under MetadataOnly; resource forks remain
separate streams. Twelve focused facade tests pass, including ASCII-fold and
binary UTF16 catalogs, exact resource payloads, source domain 11, stale deferred
EOF guards, refunds and lost-allocation rejection under both policies. This
initial read profile does not establish journal replay, general Unicode folding,
mutable HFS operations or native macOS compatibility.

HFS+/HFSX now has a dedicated bounded fuzz target and five independent seeds.
The harness traverses both forks, audits ownership, checks free-range geometry,
exercises malformed headers/allocation/truncation and verifies retained-stream
cancellation and full refunds. Fifteen fuzz smoke tests pass, including a positive
HFS audit/two-stream reachability assertion. Instrumented HFS campaign evidence
remains pending; ordinary smoke success is not substituted for that gate.

A fresh isolated snapshot at `/data/cache/partmgr-hfs-fuzz-source-dk_0ced8`
passed the packaged formatting, all-target/all-feature locked Clippy and full
all-feature locked host suite. The registry-only package receipt is
`/data/cache/partmgr-package-hfs-dk_0ced8/evidence.json`.
The expanded instrumented campaign passed all 13 targets at 1,002 iterations
per target, with no crashes or timeouts:
`/data/cache/partmgr-hfs-fuzz-source-dk_0ced8/campaign-rust199/summary.json`.
The adjacent `source-audit.json` verifies all 154 recorded source hashes against
the captured snapshot and records the Rust 1.99 toolchain pin. The initial
campaign directory retains a setup failure from omitting that pin; the completed
run uses the corrected snapshot. This snapshot evidence includes the HFS reader,
facade and fuzz harness; it does not cover later owned editor changes, native
macOS behavior, firmware or hardware power-loss durability.

Reviewed HFS+/HFSX native receipt frozen-v4 and independently verified all five
recorded engine/fixture/test hashes against the current sources. The support
matrix now records the implemented bare nonjournaled read/audit/tree profiles
and native TSK data/resource-fork evidence. Native fsck-device ioctl and macOS
validation remain open; the receipt does not certify those layers.

The optical integration now exercises an actual audited HFS+ tree containing a
resource fork. Both ISO and UDF ContentOnly capture reject the unsupported fork
before creating any staging artifact, and all retained resource leases refund.
This prevents silent stream loss; it does not implement resource-fork preservation.
The remaining preserving optical profile needs an explicit semantic mapping and
independent native round-trip evidence. The new integration regression uses the
independent classic HFS+ specification fixture rather than an optical mock tree.

Two new storage integration tests pass for owned classic ext2 replacement on raw
and QCOW2 disks. They exercise bounded WriterSession regions, exclusive target
and external journal locks, reviewed patch equality, stale handle invalidation,
native hardlinks and complete reopened logical-image/framing comparison.
Allocation/namespace/resize integration and independent native container
validation remain additional gates rather than being inferred from replacement.

Ext2 raw/QCOW2 integration now additionally passes short-read streaming extension
across the direct/single-indirect boundary and truncation freeing the indirect
block. All three transaction patch sets are reviewed against exact before-images;
hardlink-visible payloads and stale handles are verified before complete reopened
logical-image equality. Storage integration formatting and all-target/all-feature
locked Clippy remain clean. Double/triple-indirect and native fault/container
oracles are additional outstanding gates.

The native read benchmark now rejects metadata-indexing work regressions with
fixture-specific FAT/ext2 call ceilings, rather than allowing the old ext2
uncached path under a generic large ceiling. A fresh isolated-source 16-run gate
passed at 65,537 FAT and 80 ext2 setup calls; paired content, exact payload I/O,
resource and unchanged-image checks passed. Receipt:
`/data/cache/partmgr-read-bench-index-gate/20261008T001613Z-2/evidence.json`.
This establishes the numeric work envelope for the fixed dataset; controlled
runner timing and durable edit/capture workload acceptance remain incomplete.

A new FAT copy regression makes a short-read source cancel while returning its
final payload bytes. The deferred guard detects cancellation during builder
source validation, before destination emission: Cancelled, zero writes and zero
flushes, with full plan lease refunds. All four focused copy tests pass. This
specifically records preflight behavior rather than assuming every source-read
failure happens after mutation and must be InterruptedWrite.

The classic HFS reader is now exposed through explicit ReadOptions::Hfs and a
separate MDB signature candidate. The new facade regression passes both opening
policies with clean audit evidence, exact byte names, separate resource-fork
payloads, source domain 14, retained EOF staleness and complete refunds. All 13
facade tests and the full host suite pass; formatting and Clippy are clean at
this checkpoint. Independent classic HFS formatter/fork validation is underway;
TSK explicitly rejects actual classic HFS, so no TSK compatibility is inferred
from its HFS+/HFSX support. Broader native collation and mutable HFS remain open.

Classic HFS now has a separate bounded fuzz target, five independent seeds and
positive complete-audit/resource-fork reachability checks. Its free-range oracle
uses the native allocation arena offset, distinct from volume-relative HFS+
geometry. Sixteen fuzz smokes, fuzz formatting and all-target locked Clippy pass.
The expanded 14-target instrumented campaign remains pending and prior 13-target
receipts are retained only as evidence for their exact captured sources.

The expanded instrumented campaign passed all 14 targets at 1,002 iterations
per target, zero crashes and zero timeouts. Receipt:
`/data/cache/partmgr-classic-hfs-campaign-t0qgy0k9/summary.json`.
The adjacent source audit verifies all 165 recorded source hashes against
`/data/cache/partmgr-classic-hfs-source-t0qgy0k9`. This includes classic HFS
reader/fork paths but does not exercise the newly exported JFFS2 editor.

Package verification of the same captured development state remains failed:
`/data/cache/partmgr-package-classic-hfs-t0qgy0k9/evidence.json` records mid-edit
JFFS2 formatting differences. A separately formatted captured copy then failed
Clippy on an unused classic HFS native-test variable at
`/data/cache/partmgr-package-classic-hfs-formatted-o_irqhiw/evidence.json`.
Both failures are retained and reported to the owning agents; neither supports a
package acceptance claim. A fresh coherent package gate remains required.

Root reviewed owned JFFS2 recovery admission and independently reran all five
current editor tests plus all 13 facade tests. Program/erase/journal/flush-cut
recovery, tombstone resurrection prevention, inode-floor continuity, incompatible
NOR bits, PREPARED victim changes and preserved unrelated ranges pass the modeled
profiles. Recomputed-digest malformed-intent negatives and independent native
completed-history recovery remain in progress, so this is not final editor freeze.

Classic HFS native-v3 now binds compiled source and binary hashes before work,
records required tool/build provenance before use, and revalidates them after the
oracle run. Root compared 12 source/tool/build provenance rows against current
files; all matched. The adjacent review-verification.json retains this check.
TSK rejects actual classic HFS and macOS fsck remains unrun; hfsutils provides
the recorded catalog/free-count/data/resource-fork oracle. Final native source
freeze and broader collation profiles remain additional work.

Ext2 storage integration now exercises exact-byte file creation on both raw and
QCOW2 targets, in addition to replacement, indirect extension and truncation.
The created payload, reviewed full patch before/after images, stale parent handle,
resource refunds and complete reopened logical disk match all pass. Integration
formatting and all-target/all-feature locked Clippy pass at this checkpoint.

Ext2 raw/QCOW2 tests now pass directory creation, cross-directory file move and
hardlink-preserving unlink, with exact payloads, absence of removed names,
reviewed before/after patches and complete reopened logical-image equality.
Storage integration formatting and all-target/all-feature locked Clippy pass.
The classic HFS agent froze its initial profile and starts JFS reader/audit/tree
implementation; JFS owns reserved source domain 15 and remains unimplemented
until coherent code and profile evidence establish support.

Classic HFS frozen-v4 native provenance has been independently checked against
all 12 compiled source/tool/build rows, with the comparison retained in adjacent
review-verification.json. The support matrix now advertises only the implemented
bare clean alphanumeric-comparison read/audit/tree profile, preserving exact byte
names and separate forks. Extended native collation, wrappers/self-overflow,
mutable HFS and macOS validation remain open; no TSK classic-HFS claim is made.

Fresh registry-only package verification passed from separately formatted snapshot
`/data/cache/partmgr-hfs-frozen-package-source-p1hrr5qv`. Receipt:
`/data/cache/partmgr-package-hfs-frozen-p1hrr5qv/evidence.json`.
Packaged formatting, all-target/all-feature locked Clippy and full all-feature
locked host tests all pass. The earlier failed package receipts remain historical;
this receipt verifies its own captured source and does not certify later agent edits
or replace native recovery, firmware or controlled performance gates.

Ext2 raw/QCOW2 container coverage now completes the created namespace lifecycle:
nonempty-directory deletion refusal, final-link file deletion and empty-directory
delete, with expected inode-release reports and absent-path checks. All nine
commits contribute reviewed before/after patches to exact reopened logical-disk
equality. Both backend tests and integration formatting/Clippy pass. These
container host tests complement rather than replace ongoing native and recovery
fault-matrix gates.

Ext2 raw/QCOW2 container regressions now add immutable bounded-facade reopening
with RequireClean after all nine commits. Both pass complete ownership audit,
removed-name checks and full surviving 513-byte payload equality, followed by
resource refunds. Focused tests, integration formatting and Clippy pass. Native
1/2/4KiB e2fsprogs success/fault matrices are being run by the ext2 agent and are
not inferred from this same-engine host reopening evidence.

Root independently reran all seven owned JFFS2 editor tests. Nine recomputed-hash
malformed intent cases reject before any target or journal write, including wrong
state/sequence, overlap/victim geometry, regressed inode floor and malformed
publication/inode semantics. Outside-range changes and COMPLETE digest mismatch
also reject without writes. This closes the earlier semantic-negative test gap.

The first native completed-history gate is retained at
`/data/cache/partmgr-jffs2-edit-evidence-run1/jffs2-owned-nor-append-gc-v1.txt`:
independent mtd-utils inputs, completed CRC checks, single-node payload oracle,
partial-program shrink recovery and partial-erase GC recovery. Root requested
compiled-source binding plus end-of-run source/tool/binary revalidation before
final freeze. Portable restart-retain/drop-volatile and interrupted-recovery
matrices remain requested work; existing retained-buffer reopen tests do not
establish those persistence extremes. No kernel-mount or hardware power-loss
claim follows from the completed native payload checks.

Ext2 raw/QCOW2 pipeline failure coverage now passes an injected target error after
an actual container flush, preserving causal IO, NeedsRecovery gating and bound
journal rollback. The complete original 1024-byte payload is restored before
normal namespace/allocation work resumes, and final immutable audit/full-image
checks remain clean. Both focused backend tests, formatting and integration
Clippy pass. This verifies filesystem recovery atop a real container session
without claiming an atomic container/filesystem transaction.

Independent ext2 QCOW2 interpretation now passes after recovery and the complete
nine-commit namespace/allocation lifecycle. Retained evidence is
`/data/cache/partmgr-ext-container-native-20261008-v1/receipt.txt`:
qemu-img 10.2.4 reports no container errors and its raw conversion matches every
byte of the reviewed 4 MiB logical image. Oracle reads leave the container hash
unchanged, and source/tool/test executable hashes match before and after the
run. Both ordinary storage tests pass; storage formatting and all-target,
all-feature locked Clippy pass. This is independent container evidence, not an
independent ext2 parser, firmware boot or hardware power-loss result.

The strengthened ext2 container gate passed again at
`/data/cache/partmgr-ext-container-native-20261008-v2/receipt.txt`. Each version,
check and conversion invocation now retains its exact program path, argument
vector, status and both output streams. The hashed executable path is also the
path invoked by the oracle. Integration all-target/all-feature locked Clippy
passes for this revision; the earlier v1 receipt remains historical evidence.

Ext2 container negative controls also pass at
`/data/cache/partmgr-ext-container-negative-20261008-v2/control.json` and
`existing-control.json`. Running the retained test executable with an empty
tool path fails explicitly for missing qemu-img and creates no passing receipt.
An existing evidence directory is rejected before oracle work; its sentinel
content and directory entries remain unchanged. Both failed invocations retain
their output and exit status. These controls verify enabled-gate failure and
evidence preservation, rather than relying on ignored-test status.

The exFAT raw/QCOW2 integration now includes an independent qemu-img gate after
replacement, extension and truncation. All three focused tests, including the
explicit native oracle, pass. Retained evidence is
`/data/cache/partmgr-exfat-container-native-20261008-v1/receipt.txt`; the converted
4 MiB logical disk matches every reviewed byte and the oracle leaves the QCOW2
hash unchanged. Commands, outputs and source/tool/test executable revalidation
are retained. This closes the independent exFAT container interpretation gap;
it does not establish crash recovery, native filesystem interpretation or boot.

After root-filesystem capacity returned, the six frozen JFS-owned files were
copied from `/data/cache/partmgr-jfs-draft` into the shared repository with atomic
replacement and byte equality checks. Publication hashes are retained in
`/data/cache/partmgr-jfs-native-v6/shared-publication.json`. All five ordinary
JFS tests pass in the shared checkout. Native v6 evidence establishes formatter,
fsck allocation/reference and debugger directory/inode agreement for the Linux
profile, including sparse/unwritten extents, external extent/directory leaves,
nested directories and hardlinks. Independent whole-file extraction and exact
Unicode display remain explicit gaps; TSK JFS support was attempted and rejected.
Common ReadImage facade/fuzz wiring and broader profiles remain pending.

JFS is now wired into the common ReadImage facade with explicit read/audit caps
and a bounded primary-superblock signature candidate. Inventory always performs
the complete implemented-profile audit, so MetadataOnly still reports the clean
evidence actually obtained. All fourteen facade tests pass, including the new
JFS exact UTF16/sparse/unwritten stream, source-domain 15, stale EOF and refunded
lease checks under both policies. Probe read-count expectations now include the
additional bounded JFS signature read. Fuzz wiring and broader profiles remain
open.

The JFS facade regression now also rebuilds a self-consistent allocation map
with an allocation/reference defect and verifies both RequireClean and
MetadataOnly refuse inventory and refund all leases. This directly checks that
the inspection policy cannot bypass JFS's mandatory complete-profile audit.

Added JFS to the fuzz dispatcher and target manifest with a 2 MiB input ceiling,
32 MiB shared budget and explicit decoder/audit work caps. Independent clean,
log-state, mirror, geometry and truncation seeds exercise indexed directories,
streams, extent visits, retained cancellation and lease refunds. All seventeen
fuzz-library smoke tests pass, including a positive JFS clean-audit/data-stream
reachability assertion. This adds harness coverage; an instrumented JFS campaign
is still required and earlier fourteen-target receipts do not cover this target.

Launched a fresh fifteen-target instrumented campaign, including JFS, from the
isolated snapshot `/data/cache/partmgr-jfs-fuzz-source-n8499f4x`; evidence output
is outside the source tree at `/data/cache/partmgr-jfs-fuzz-campaign-n8499f4x`.
The runner now hashes recorded sources again after all targets and fails if
start/end manifests differ. This supplements snapshot isolation with an explicit
source-stability check. The campaign is in progress; no passing campaign claim
follows from its launch or the earlier ordinary smoke tests.

ExFAT raw/QCOW2 integration now fails acknowledgement after an actual container
flush, requires NeedsRecovery, blocks the old file handle, and rolls back through
the real external FileStorage undo journal before normal edits. Original payload
readback and Ready state pass. All three focused tests, including independent
qemu-img interpretation of the final whole disk, pass; current receipt is
`/data/cache/partmgr-exfat-container-native-20261008-recovery-v3/receipt.txt`.
The v2 attempt failed the test's lease assertion because retained file/failure
objects had not yet been dropped; explicit lifetime completion fixes the test.
The failed evidence directory remains retained. This models failed host-barrier
acknowledgement, not physical power loss or atomic container rollback.

The fifteen-target campaign completed successfully: every target, including
JFS, ran 1002 instrumented iterations with zero crashes and timeouts. Receipt:
`/data/cache/partmgr-jfs-fuzz-campaign-n8499f4x/summary.json`. Root independently
checked all 174 recorded source hashes against the snapshot and start/end
manifests, each target's final native summary and every seed hash; audit:
`source-audit.json` beside the receipt. This is bounded coverage-guided smoke for
the captured source, not security qualification. It does not fuzz the new owned
JFFS2 editing API or establish later ext4/APFS changes.

Root verified all fifteen source rows in the final JFFS2 owned-edit native
receipt against the restored shared checkout; correspondence is recorded in
`/data/cache/partmgr-jffs2-edit-evidence-final2/root-source-review.json`.
This includes the formerly truncated native test, which is now complete and
matches the source-bound final receipt. Fresh packaged acceptance is running
from `/data/cache/partmgr-jfs-package-source-xqhxk4xf`, with output outside the
snapshot at `/data/cache/partmgr-jfs-package-acceptance-xqhxk4xf`. Its outcome
remains pending and does not establish newer agent drafts.

The retained exFAT recovery container executable also passes missing-tool and
existing-evidence negative controls. Evidence:
`/data/cache/partmgr-exfat-container-negative-20261008-recovery-v3/control.json`.
Both invocations fail explicitly, produce no passing receipt and preserve
existing evidence bytes/entries. Their exit status, outputs, argument vector and
executable hash are retained.

Fresh self-contained packaged acceptance passed from the JFS-integrated
snapshot: `/data/cache/partmgr-jfs-package-acceptance-xqhxk4xf/evidence.json`.
All six commands succeeded, including packaged fmt, all-target/all-feature
locked Clippy and the complete all-feature locked host suite. Root independently
verified the crate artifact, every retained command log, every extracted-file
hash and absence of path/git dependencies in the normalized manifest; review:
`root-audit.json` beside the receipt. This covers that exact package, including
restored JFFS2 tests and JFS facade integration, not later APFS/ext4/namespace
drafts, publication, firmware or portable-target acceptance.

Added actual JFS common-tree to ISO/UDF ContentOnly integration. The native
unpaired-surrogate fixture is rejected by both writer paths before a staged
artifact exists. An independently adjusted ASCII-name fixture retains its JFS
hardlinks/nested sparse/unwritten structures; both optical images reopen and
return the complete deferred source payload exactly, including zero ranges.
Dropping staged output removes it and dropping the source refunds all leases.
The focused integration test passes. This establishes host pipeline behavior;
it does not claim native optical extraction or metadata-preserving capture.

Added an enabled independent JFS optical extraction gate requiring a fresh
PARTMGR_JFS_OPTICAL_EVIDENCE directory and optional explicit extractor path.
Native attempts are retained at `/data/cache/partmgr-jfs-optical-native-20261008-v1`,
v2 and v3. ISO primary names are uppercase in 7-Zip's selected namespace;
correcting that selection yields exact ISO extraction. UDF sparse allocation is
rejected as Unsupported Method by both p7zip 17.05 and 7-Zip 26.02. The gate
therefore fails, produces no passing receipt and remains an explicit independent
UDF extraction gap. Same-engine host reopen still passes; it does not replace
the missing native extraction evidence. No production writer profile was
silently changed to work around the independent tool limitation.

Independent follow-up extracted `/zbx` from the retained v3 UDF image using
libudfread 1.1.2's native file API via ctypes. All 16391 bytes match the separate
7-Zip ISO extraction, including sparse/unwritten zeros; EOF and unchanged image
hash checks pass. Receipt:
`/data/cache/partmgr-jfs-optical-libudfread-20261008/receipt.json` records the image,
library and payload hashes. This demonstrates independent UDF extraction for
the retained image and identifies a 7-Zip limitation; the integrated ignored
gate still requires updating to this successful oracle and a fresh source-bound
rerun before claiming integrated native acceptance.

The integrated native JFS optical gate now passes using 7-Zip for ISO and the
checked-in `scripts/udf-native-extract.py` helper with explicit libudfread for UDF.
Fresh source-bound evidence:
`/data/cache/partmgr-jfs-optical-native-20261008-v4/receipt.txt`. Both complete
payloads match, oracle reads leave retained images unchanged, and script/library/
Python/test executable plus recorded JFS source hashes revalidate at completion.
The compiled test and helper must match live bytes. Actual extractor commands,
stdout and stderr are retained. Both focused tests pass; current shared APFS
draft emits warnings, so no fresh full-Clippy claim accompanies this checkpoint.
Native JFS input extraction and metadata-preserving capture remain open.

JFS optical v5 strengthens the payload oracle: expected bytes are reconstructed
directly from the independent fixture's two recorded block patterns and known
hole/unwritten ranges, rather than derived solely by reading the source engine.
The JFS stream, reopened optical readers and both native extractors must match
that same independent model. Both focused tests and native extraction pass;
receipt: `/data/cache/partmgr-jfs-optical-native-20261008-v5/receipt.txt`.
The retained executable also rejects missing libudfread configuration and creates
no passing receipt; control:
`/data/cache/partmgr-jfs-optical-negative-20261008-v5/control.json`.

The JFS optical native gate now extracts all three regular-file occurrences:
zbx, its Alias hardlink name and Box/Child. Both ISO and UDF outputs match the
independent block/zero model or exact `nested!` bytes. Each command has separate
retained outputs and checks the image remains unchanged. Fresh passing receipt:
`/data/cache/partmgr-jfs-optical-native-20261008-v7/receipt.txt`. The v6 attempt
used a lowercased UDF alias and correctly failed native lookup; corrected exact
case passes without altering native names. Both focused tests pass. This checks
payload at every captured file occurrence, not preservation of hardlink identity
in every destination namespace.

Deferred JFS optical failure coverage now injects IO at the first recorded data
block after complete metadata inventory succeeds. Both ISO and UDF staging must
retain the specific causal read error, remove partial staged output, restore the
pre-staging resource baseline, and refund all source leases when dropped.
Both ordinary JFS capture tests pass against the accepted frozen package source
`/data/cache/partmgr-jfs-package-source-xqhxk4xf`. Current shared compilation was
temporarily blocked by in-progress APFS field visibility/initialization; this
isolated check does not establish acceptance of those new draft changes.

Shared-checkout verification is now restored: both ordinary JFS optical tests
and the enabled native gate pass, with refreshed receipt at
`/data/cache/partmgr-jfs-optical-native-20261008-v8/receipt.txt`. Root corrected a
misplaced public JFFS2 hash-method doc comment that blocked shared compilation.
All fifteen ordinary optical integration tests pass, plus optical formatting and
all-target/all-feature locked Clippy. Native gates other than JFS were not rerun
by this ordinary-suite check; broader APFS/ext4/JFFS2 work remains in progress.

Added actual audited JFS common-tree to classic ext2 ContentOnly copy coverage.
The destination's fresh complete audit passes; its two root hardlink names share
one object identity, all recorded/hole/unwritten logical payload bytes match an
independent fixture model, and the nested child yields exact `nested!` bytes.
UTF16 conversion is explicit and an unpaired surrogate fails planning before
output is emitted. The FAT copy profile remains unavailable for this hardlinked
source; ext2 supports the required identity preservation. All five ordinary
ext-copy tests pass. This host destination-reader check does not establish an
independent native destination oracle or preservation of source metadata.

Independent JFS-to-ext2 destination verification now passes. The enabled
e2fsprogs gate checks e2fsck -fn success, extracts every file with debugfs against
the independent fixture model, and verifies native inode equality for zbx/Alias
and a distinct nested-child inode. The image remains byte-identical after these
oracle reads. Fresh receipt:
`/data/cache/partmgr-jfs-ext-copy-native-20261008-v1/receipt.txt`. Test executable,
recorded source/lock and tool hashes match before and after; compiled test bytes
must match the live source. Engine source hashes are live start/end bindings,
not embedded compiled-engine proofs. Native JFS source extraction and source
metadata preservation remain explicit gaps.

The strengthened JFS-to-ext2 native recipe passes again at
`/data/cache/partmgr-jfs-ext-copy-native-20261008-v2/receipt.txt`. Every native
version, filesystem check, payload extraction and inode inspection now uses the
resolved tool path and retains exact arguments, exit status, stdout and stderr.
Both tools' versions and start/end hashes are bound alongside the compiled test,
recorded sources and destination image. The initial compile attempt encountered
an in-progress APFS import; its owner corrected it before the passing rerun.

Actual JFS copy source-stability tests now distinguish the write boundary.
A length change after planning but before emission returns StalePlan with zero
writes and a completely unchanged destination. A source change triggered by the
destination flush returns InterruptedWrite after actual writes, never success
or a rollback claim. Both paths release their plans and source-map leases.
All six ordinary ext-copy tests pass; earlier native copy receipts remain tied
to their captured test revisions.

APFS is now wired into ReadImage with explicit container bounds, checkpoint/
object caps, allocation-audit caps and caller-selected native volume identifier.
There is no automatic first-volume fallback. NXSB is only a bounded signature
candidate. Inventory always audits the implemented profile under both policies.
All sixteen facade tests pass, including APFS wrong-volume rejection, native
byte names, separate resource fork, source-domain 16, stale EOF and refunded
leases. This fixture-based facade result does not complete broader APFS
checkpoint/snapshot/shared-allocation/native interoperability requirements;
the APFS agent's deeper acceptance work continues.

Added bounded APFS fuzz dispatch and target configuration. Independent clean,
checksum-damaged, rehashed geometry and truncation seeds exercise container
checkpoint validation, an explicitly selected advertised volume, complete audit,
directory/stream traversal, deferred cancellation and resource refunds. Input is
capped at 2 MiB with 64 MiB shared budget and explicit checkpoint/object/work
caps. All eighteen fuzz-library smoke tests pass; the positive APFS smoke must
reach a clean audit and a two-stream file. This is harness reachability, not an
instrumented campaign claim; the earlier fifteen-target receipt excludes APFS.

Immutable ext facade selection now has explicit ReadOptions::Ext for supported
ext2/ext3/ext4 profiles. Existing ReadOptions::Ext2 rejects extent-enabled or
journal-bearing geometry rather than silently broadening its classic contract.
Accepted images report Ext4 for extent profiles, Ext3 for inactive-journal
classic maps, or Ext2 for classic nonjournaled maps. All seventeen facade tests
pass, including a clean independently constructed extent image that requires
the new opt-in. Editor authority remains separate and classic-only. Default
ext4 feature layouts, journal replay and broader native acceptance remain open.

Added an independently assembled extent seed to the existing bounded ext fuzz
target. The positive smoke reaches complete clean allocation accounting and
checks recorded data, hole zeros and unwritten zeros despite poisoned backing
blocks. All nineteen fuzz-library smoke tests and all-target locked fuzz Clippy
pass. This is harness reachability evidence; the earlier fifteen-target
instrumented campaign does not cover the new seed or APFS target.

Owned JFFS2 fuzzing now reaches bounded file creation in both native byte orders
using the independent reader fixture, exclusively owned mutable NOR backend,
disjoint external journal and seven-byte short writes. Successful cases reject
the stale parent identity and release the editor before a fresh immutable
complete-audit tree verifies exact created payload bytes. All twenty library
smokes pass, including positive owned-create reachability in both byte orders;
all rejected and completed cases require complete reservation refunds. This
functional modeled-flush coverage does not replace persistence-cut native
evidence or establish a new instrumented campaign.

The new isolated sixteen-target instrumented campaign passed 1,002 iterations
per target with zero crashes/timeouts. Receipt:
`/data/cache/partmgr-filesystem-fuzz-campaign-1p76ih84/summary.json`.
Root verified all 190 source hashes against start/end and the immutable snapshot,
each seed hash and each native log summary in adjacent `source-audit.json`.
This checkpoint includes APFS, the extent seed and owned JFFS2 creation; it does
not cover subsequent broader ext/APFS or multi-node JFFS2 changes. Complete
all-feature locked host tests, all-target/all-feature locked Clippy with warnings
denied, and formatting also pass in the shared checkout at this checkpoint.

The bounded JFFS2 namespace/symlink-GC native checkpoint passed at
`/data/cache/partmgr-jffs2-namespace-native-final2/jffs2-owned-nor-append-gc-v1.txt`.
Root's adjacent `root-source-review.json` binds all sixteen recorded source rows
to the isolated fuzz snapshot and confirms terminal source/tool/executable
revalidation. Seventeen editor tests include namespace and live-symlink GC
mutation/recovery cuts under four persistence combinations. Independent tools
establish completed CRC and regular payload evidence; symlink interpretation
remains framework-only, with no physical power-loss or mounted rename claim.
The agent continues generalized multi-node range editing rather than treating
this bounded checkpoint as completion of the full roadmap.

Actual APFS common-tree input now has ext2 capture rejection coverage: the
complete-audited independent APFS fixture advertises its resident resource fork,
and ExtCopyPlan rejects that extra stream during planning with Unsupported.
The source's retained budget returns to its baseline after rejection and fully
refunds after release. This demonstrates the explicit destination limitation,
not successful APFS capture or resource-fork preservation. All seven ordinary
ext copy tests pass; the two enabled native gates remain separate checks.

All three copy examples now expose explicit `--source-profile ext` through the
immutable facade with complete clean audit and bounded inventory; `ext2` keeps
the classic feature gate. Examples compile. An actual extent-seed CLI capture
into 16 MiB classic ext2 passes deferred copy, destination audit and publication,
reporting Ext4 source family; the same source under `ext2` rejects before any
destination exists. Commands, output and source/binary hashes are retained at
`/data/cache/partmgr-ext-profile-cli-oii0pk7s/receipt.json`. This functional CLI
evidence is not an independent native destination oracle. Focused Clippy
currently finds two collapsible-if warnings in the concurrent JFFS2 helper;
its owner has been notified, so no fresh green Clippy claim is made here.

Independent destination verification now strengthens that same CLI artifact.
`e2fsck -fn` returns zero; `debugfs` extracts all 4,096 expected bytes (1,024
recorded bytes of 73 followed by hole/unwritten zeros) and resolves both `/alias`
and the exact non-UTF8 byte name to the same inode with two links. Exact tool
paths, versions, argument bytes, status/output digests and complete outputs are
retained at `partmgr-ext-profile-cli-oii0pk7s/native/receipt.json` under
`/data/cache`. Image and tool hashes remain unchanged through verification.
This establishes the destination's native content/name/hardlink evidence; the
source fixture itself and firmware boot remain separate claims.

Root audited the frozen initial APFS v4 native artifacts independently:
six archived source hashes match the receipt's identical start/end bindings;
the populated image matches its retained digest; checker/extractor commands
completed successfully; independently calculated 16,397-byte sparse data and
exact resource/nested payloads match native outputs. Exact native file naming
is confirmed through istat, with fls display limitations retained. Root audit:
`/data/cache/partmgr-apfs-native-v4/root-audit.json`. The support matrix now
records the initial APFS, immutable ext3/extent-ext4 and JFFS2 namespace profiles
instead of stale Planned rows. Experimental Linux APFS evidence does not
establish macOS acceptance or later multi-volume/checkpoint implementation.
The seven ordinary common ext copy tests also pass after shared build coherence
returned; native copy gates were not rerun by that host command.


Added explicit optical resource-fork transformation policy rather than silently
broadening ContentOnly. UDF maps a non-root fork to the named stream
com.apple.ResourceFork and reports the transformed fork count; ordinary
ContentOnly and ISO still reject. Actual audited APFS facade input now passes
UDF 2.01 staging and independently calculated full sparse payload/resource-byte
roundtrip, owning-object relation, default rejection and cleanup/refund checks.
The complete ordinary optical suite passes; independent native UDF fork
extraction and metadata-fidelity evidence remain open.


Resource-fork transformation checks now reject explicit fork mapping into ISO
and UDF 1.02 without staged artifacts or leaked reservations. The actual audited
HFS+ tree also captures through the explicit UDF 2.01 policy: exact RSRC! bytes
and the separately advertised empty resource fork retain owning-object relations
and transformation counts. Both APFS/HFS+ optical tests and integration
all-target/all-feature locked Clippy pass. Native fork semantics remain a
reported transformation, with independent destination stream extraction open.


The immutable ext facade now uses geometry.is_classic() for the Ext2 contract,
so the new 256-byte inode reader cannot silently enter the classic-only route.
Supported broader geometry requires explicit Ext options; all seventeen facade
tests pass at this checkpoint. New 256-byte native/negative acceptance is still
owned by the ext agent and is not established by these earlier facade fixtures.


Optical mapping collision coverage now exercises an existing named stream whose
native byte or UTF16 spelling becomes com.apple.ResourceFork. Both reject as a
duplicate mapped stream before staging, with complete reservation refunds and
no output artifact. All five optical writer tests pass. Broader integration
Clippy encountered temporarily incoherent APFS multi-volume fixture leaf calls;
the owning agent was notified, and this does not establish a broad green check.


Existing caller regression checks pass against the expanded APFS audit:
all twenty fuzz-library smokes, seven ordinary ext copy tests and formatting.
The facade additionally selects both explicit volume OIDs from the independent
multi-volume fixture after checkpoint advancement: the first retains its exact
native file namespace, while the second remains empty, with complete clean
container evidence and full refunds under an explicit 256 MiB pool. All eighteen
facade tests pass. This fixture integration does not extend the older initial
profile native receipt to historical/multi-volume acceptance.


APFS fuzz corpus now includes independent multi-volume, retained-checkpoint and
rehashed unsupported unselected-volume images under an explicit 256 MiB shared
pool (2 MiB input and existing object/checkpoint/work caps remain). Positive
smoke requires clean complete 57-block accounting for both selected volume OIDs;
a negative smoke requires Unsupported for an unselected volume while restoring
baseline reservations. All twenty-two fuzz library tests pass. The previous
sixteen-target instrumented receipt does not cover these later seeds/audit work.


Independent facade fixture coverage now proves the extended ext inode boundary:
its inode table expands to four blocks, directory/data move to separately
allocated blocks, and native 256-byte strides contain explicit extension sizes.
Classic Ext2 rejects/refunds before inventory; explicit Ext completes clean
accounting and reads all expected payload bytes. All nineteen facade tests pass.
This fixture test complements the agent's separately source-bound 42-image
extended-inode/JBD native checkpoint; default ext4 metadata/checksum/hidden
allocation feature layouts remain under coordinated development.


The ext copy CLI now supports optional GPT/MBR partitioned raw output with
separate bounded filesystem emission, table commit/reopen and final region audit
before no-clobber publication. Both routes pass actual extent-source CLI runs;
independent raw field decoding verifies LBA2048/32768sectors, and native tools
validate complete extracted filesystem/payload. Receipt:
`/data/cache/partmgr-partitioned-ext-cli-umialil5/receipt.json`. Focused example
Clippy passes. This advances partitioned builder orchestration; independent
container conversion, broader sinks and firmware acceptance remain open.


The independent APFS checker subsequently exposed a geometry defect in the new
small multi-volume fixture: the native maximum-volume field depends on container
capacity, and a 2 MiB container cannot advertise two volumes. Earlier facade/fuzz
passes for that fixture establish parser behavior only, not specification-valid
multi-volume support. The owner is replacing it with a sparse logical container
above 512 MiB and valid chunk metadata; facade/fuzz adapters must follow that
correction before the new profile is accepted. The older single-volume native
receipt remains a separate valid checkpoint.


Added reproducible independent normal/compressed QCOW2 conversion validation in
scripts/filesystem-container-check.py. Both newly partitioned GPT/MBR CLI
artifacts pass qemu-img check/compare, conversion back and complete logical
size/SHA256 equality, with source/tool hashes unchanged and exact command logs.
Receipts are retained below partmgr-partitioned-ext-cli-umialil5 in gpt-conversion
and mbr-conversion. This establishes separate container-stage logical equality,
without firmware or cross-layer atomicity claims.


The APFS multi-volume geometry correction is now integrated into facade/fuzz
sources: retain a 2 MiB prefix, declare a 536,875,008-byte sparse logical source,
and serve checked zero-tail reads. Native maximum-volume/chunk geometry is now
size-consistent; read/audit block bounds explicitly increase to 131073. No whole
logical image allocation is introduced. All nineteen facade and twenty-two fuzz
smoke tests pass with corrected fixtures. Independent sparse native profile
acceptance remains the agent's separate gate, so earlier tiny-fixture results
are not promoted to native support.


Partitioned ext CLI errors now retain an explicit failed stage and original
causal error through emission, table planning/commit/reopen and filesystem
reopen/audit. Unpublished staging drops on failure; rebuilding new output is
separate from already-published directory-sync uncertainty. The example compiles.
This improves the required multi-layer recovery report without claiming atomic
rollback across table/filesystem/container layers.


Owned JFFS2 fuzzing now reaches multi-node inode-preserving range transactions
in both byte orders. Aligned inputs declare a minimum64KiB erased-capacity
region; payload160/node64/journal32768/pool8MiB caps remain explicit. The smoke
requires three data nodes, ZERO extension-gap bytes, short programming, stale
identity rejection, exact independent payload model, audited immutable reopen
and shared observed hardlink identities, with complete refunds. Fuzz-mutated
names are never assumed to retain fixture spellings. All twenty-three fuzz
smokes and all-target locked fuzz Clippy pass. The previous campaign excludes
this continuation; native final4 and persistence-cut evidence are separate.


The immutable profile fuzz checkpoint is now independently audited at
`/data/cache/partmgr-profile-fuzz-campaign-g2uq0f6x/root-audit.json`: 194 retained
source hashes, all sixteen manifest targets and input caps, all seed hashes and
terminal log summaries match. Each target completed 1,002 iterations with zero
crashes/timeouts. This includes corrected sparse APFS multi-volume/history and
JFFS2 shared-inode multi-node range paths; subsequent live agent drafts are excluded.

APFS native v11 now has an adjacent root audit verifying six retained source
bindings, identical start/end provenance, tool hashes, command outcomes and whole
image digests. The single-volume independent 16,397-byte sparse payload, resource
and nested files match exactly. The corrected sparse two-volume/history image
is 536,875,008 bytes; native TSK reports both OIDs and 449 allocated blocks.
Experimental Linux evidence does not establish macOS acceptance or the newer
hardlink/clone-sharing draft. Support and identity-scope documentation now reflect
these frozen profiles, the extended-inode ext checkpoint and JFFS2 range checkpoint.

The retained profile snapshot also passes cargo fmt, all-target/all-feature
locked Clippy with warnings denied, and all-feature locked host tests. Adjacent
`host-checks.json` records terminal commands and verifies all 195 captured files
remain unchanged; this snapshot excludes repository examples/integrations and
later agent drafts, and full host output was not separately archived.

A new common-facade FAT12 concurrency regression passes: four readers share one
retained file after image drop, execute 256 random/short-EOF requests with exact
content and stable identities, require exactly one backend read per request,
and check request/owner cancellation plus fixed reservations and final refunds.
All twenty facade tests pass. The APFS fixture signature lint was corrected by
its owner, and focused facade Clippy subsequently passed.
This enforces a direct-read work/lifetime
contract without substituting it for controlled performance acceptance.


FAT and exFAT destination CLI pipelines now support optional GPT/MBR framing
through a shared example helper. Filesystem emission uses an exclusive bounded
region; its handle closes before table commit/reopen, then a fresh region audit
precedes nonclobber publication. Early destination refusal and causal stage
errors preserve the staged-output contract. Native single-file acceptance covers
all eight FAT12/16/32/exFAT × GPT/MBR cases at
`/data/cache/partmgr-fat-exfat-partition-cli-qjackg2g/receipt.json`; independent
table fields/CRCs, native checks and full TSK payload agree. Fresh final source
bindings and retained executables/check script prevent promotion of an earlier
pre-error-reporting checkpoint. Earlier FAT32/GPT and exFAT/MBR artifacts also
pass normal/compressed QCOW2 complete logical-byte round trips, recorded below
`/data/cache/partmgr-fat-exfat-partition-cli-0akh7fo4/`. Cross-layer atomicity
and firmware acceptance remain unproven.


Final partitioned-copy images are byte-identical to the preceding eight-image
checkpoint. Adjacent `container-equivalence.json` verifies that the final
FAT32/GPT and exFAT/MBR image hashes equal both start/end source hashes of the
passed normal/compressed QCOW2 receipts. The examples and facade pass focused
Clippy. The latest full live checks encountered concurrent ext4 directory
validator lint/format draft work; their owners are resolving those before a
fresh coherent all-target acceptance checkpoint.

After the owners completed their new staged validator/test formatting, the full
live cargo fmt check and all-target/all-feature locked Clippy with warnings
denied pass. The already-started all-feature locked host suite is still running
its new exhaustive multi-node JFFS2 GC persistence-cut case (session60586);
observation waits have not restarted that live process. This live lint result
is separate from the immutable snapshot host acceptance recorded above.


Added scripts/filesystem-native-partition-copy.py as a repeatable ten-profile
GPT/MBR copy acceptance gate, with independent reciprocal header/array CRC/type
checks, native nonrepair source/destination checks and complete extraction.
The immutable pvhzho3d receipt and root audit verify ten images, seventy command
logs, ninety-seven archived source files and three retained executables. Native
source validation rejected an empty boot-sector label in the initial handcrafted
fixture; the fixture now has valid independent boot/label fields rather than
accepting repair diagnostics. Ext2 exact-byte names retain raw short-name spaces;
its extraction request now checks that exact namespace instead of assuming a
dotted display name. Missing Cargo fails before build/output.

APFS v13 and JFFS2 GC final2 received independent root audits. APFS both clone
representations have exact 16,397-byte native payloads, two original hardlinks,
203 allocated blocks and checker output without warnings; multivolume/history
remains 449 blocks. JFFS2 native GC has the exact retained 5013-byte payload/raw
image/binary and all eighteen source files archived, including an exact-hash
main source recovered from root's earlier immutable snapshot. New writable/
packing continuations remain separate. The allocator already packs aligned nodes
inside pristine erase blocks; the remaining packing restriction is partially
occupied-block reuse, not one-node-per-block allocation.

The full live host suite completed successfully, including the113-second
JFFS2 GC recovery test. A later packaged-source attempt17f95q16 correctly failed
formatting on a concurrently captured diagnostic test draft; no package acceptance
is claimed for that archive. A fresh coherent package gate remains required.


Root independently verified packed-pristine GC v5: all23 serialized journal
records are contiguous/aligned, total6584 bytes in one64KiB destination block
after the reserved12-byte prefix, and full journal/image/binary/receipt hashes
match. The5013-byte native extraction equals the independent expected payload.
All eighteen baked source bindings are now archived from exact-hash matches in
the fresh316-file package source snapshoto1bteojl. Its package gate is running
in session84093; no acceptance claim until terminal validation and archive audit.

Packaged snapshot o1bteojl passed formatting but correctly failed strict Clippy
on a nested conditional in the staged ext audit (src/fs_ext_audit.rs:282).
The failed receipt remains retained; it is not package acceptance. A future
coherent snapshot must pass all packaged gates after the ongoing stage wiring.

Added published flate2 1.1.10 with default features disabled and rust_backend
selected for the compressed JFFS2 reader continuation. This version was already
resolved transitively; all four locks now include it as a partmgr dependency,
with no registry package upgrades. Locked offline Cargo metadata passes for root,
fuzz, storage and optical manifests. The planned fixed-buffer decoder uses the
[official low-level Decompress API](https://docs.rs/flate2/1.1.10/flate2/struct.Decompress.html)
with input/output/decoder-state reservations and explicit consumption, stream-end
and checksum checks; compressed-node support remains unaccepted until code,
malformed-data tests and native evidence pass. Owned compression/editing profiles
are not widened by a dependency declaration.

Frozen checkpoint japna_nk subsequently passed packaged-source acceptance:
`/data/cache/partmgr-read-profile-package-japna_nk/evidence.json` and its
adjacent root audit verify all six commands, 249 packaged files, 321 snapshot
files, retained test binaries and registry-only dependencies. Formatting,
all-target/all-feature locked Clippy and all-feature locked host tests passed
on the extracted package. This checkpoint predates the compressed JFFS2 facade
and production modern ext handoff; those later changes need fresh acceptance.
The earlier failed package receipts remain failed historical evidence.

The same frozen source passed sixteen native FAT32/classic-ext2 benchmark runs
in `/data/cache/partmgr-read-profile-bench-japna_nk/20261008T061551Z-2/`.
The root audit verifies eight paired content comparisons, exact payload backend
calls/bytes, source and image hashes, and command logs. Copied extent maps are
now charged before allocation and all benchmark memory leases must refund.
These uncontrolled timing measurements do not establish timing thresholds or
acceptance of broader ext workloads.

Expanded partition-copy receipt
`/data/cache/partmgr-partition-native-mk5w0v54/receipt.json` and adjacent root
audit verify ten GPT/MBR images and thirty complete native payload extractions.
Each independently authored source contains a 512-byte root file, a fragmented
4099-byte root file and a fragmented 1025-byte nested file. Exact ext2 names
retain raw short-name spaces. This binds the expanded verifier to its archived
earlier engines/examples; subsequent engine changes, QCOW2 conversion of these
new images, firmware and cross-layer atomicity remain separate gates.

The facade now exposes explicit Jffs2Compressed read options with bounded
RTIME/ZLIB decoding. Independent LE/BE tests cover both allocation policies,
strict-profile rejection, decompression caps, checksummed malformed RTIME,
retained lazy reads, stale lengths, owner cancellation and complete refunds.
All twenty-one facade tests pass. This does not enable compressed owned editing
or imply acceptance of the remaining JFFS2 codecs.

Focused frozen benchmark receipt
`/data/cache/partmgr-ext-bench-gate-qg6_v69o/receipt.json` binds the executable
to the preceding benchmark receipt. Explicit ext mode reads an independent
4096-byte extent fixture in both direct and filesystem modes, matching the
independent whole-payload hash and exact backend work. Classic ext2 mode rejects
that same image. This is focused extent-profile evidence, not modern ext native
or controlled performance acceptance.

JFFS2 fuzz dispatch now exercises strict and explicit compressed readers for
both byte orders, including deferred reads, native tree/audit, cancellation and
refunds. New independently checksummed RTIME seeds include positive 256-byte
expansion and malformed 255-byte expansion. Both focused fuzz smoke tests pass;
a fresh source-bound mutation campaign remains required for this extension.

Root audited the immutable compressed reader's final native receipt at
`/data/cache/partmgr-jffs2-codec-native-final/root-audit.json`: all ten exact
source files are archived, tool/binary hashes match, and four LE/BE RTIME/ZLIB
cases each have twenty-four compressed nodes and a complete 98,304-byte native
extraction matching the independent model. This freezes reader evidence before
the later facade/fuzz/compressed-builder changes and grants no owned compressed
editing or physical flash acceptance. Current root formatting, all-target/
all-feature locked Clippy, twenty-one facade tests and all-target fuzz Clippy
pass. The full live all-feature locked host suite is running in session72295.

The broadened fuzz library suite passes all twenty-four tests after retaining
the original strict LE/BE seed positions required by owned-editor smoke tests.
The new compressed seeds are appended to that corpus; final all-target locked
fuzz Clippy also passes. This verifies smoke coverage and preserves the strict
editor test contract, without substituting for a mutation campaign.

Session72295 completed successfully: the full all-feature locked host suite
passes, including all thirty JFFS2 editor tests and the109-second exhaustive GC
mutation/recovery case. Native prerequisites remain explicitly ignored in this
host run and use their separate evidence gates. This is a live host checkpoint,
not a frozen package or firmware acceptance claim.

Added an actual compressed JFFS2 common-tree-to-ext2 capture regression for both
byte orders. Independent native RTIME nodes feed the facade and copy plan;
reopened ext2 clean audit verifies the full256-byte payload, exact nonUTF8 nested
name, shared hardlink identity, retained reads and complete refunds. All eight
ordinary ext-copy tests pass (two native gates remain separate), and focused
Clippy passes. This host pipeline evidence does not imply native kernel capture
or compression preservation in the destination.

Root audits now bind both compressed offline builder v2 receipts in
`/data/cache/partmgr-jffs2-build-{rtime,zlib}-native-v2/root-audit.json`:
eight images per codec, full90,013-byte independent extracted payloads, exact
symlink targets, enumeration-order deterministic image pairs, tool/fixedbinary
hashes and fourteen archived source files. The original baked test source was
recovered with its exact hash from the retained binary. Subsequent strengthened
builder tests require their own final acceptance; these receipts do not enable
compressed owned editing/GC or physical flash operations.

Integrated independent modern ext fixtures into fuzz seeds: two clean
metadata-checksummed images (extent and direct-map variants) and four checksum-
aware corruptions for shared EA references, EA/data aliasing, inode CRC and
reserved GDT data. The ext harness now has an explicit4MiB pool and asserts
complete refunds. New smoke proves public clean audit, exact1700-byte retained
payloads and EOF cancellation for both clean variants. All twenty-five fuzz
library tests and all-target locked fuzz Clippy pass. Native production modern
ext acceptance and the expanded instrumented campaign remain separate gates.

The new selective instrumented campaign passed both expanded targets at
`/data/cache/partmgr-compressed-modern-fuzz-campaign-xjjwwhss-bfd/summary.json`.
Its root audit verifies209 source bindings against the immutable324-file
snapshot, both seed sets, log digests and summaries:1001 iterations each,
zero crashes/timeouts and unchanged sources. This excludes other targets and
later changes. The initial campaign directory without the-bfd suffix failed
before mutations because honggfuzz's native build lacked bfd.h; it remains
failed evidence. The successful run used nix-shell with binutils-unwrapped.dev,
libunwind and pkg-config while retaining pinned Rust1.99.0 first on PATH.
Current formatting and all-target/all-feature locked root Clippy pass.

Started packaged-source acceptance for this immutable expanded checkpoint in
session49731, output `/data/cache/partmgr-compressed-modern-package-xjjwwhss`.
It must reach terminal success and root archive audit before any new package
acceptance claim; the earlier japna_nk package acceptance retains its narrower
historical scope.

Packaged-source session49731 completed successfully. Root audit at
`/data/cache/partmgr-compressed-modern-package-xjjwwhss/root-audit.json` verifies
252 packaged files, the324-file immutable snapshot, all six command/log hashes,
all retained test binaries, original manifest identity and registry-only
normalized dependencies. Extracted-source formatting, strict all-target/
all-feature locked Clippy and full all-feature locked host tests pass. This
checkpoint includes modern ext and compressed JFFS2 facade/capture work, but
excludes the later APFS facade reauthoring test and final strengthened builder
tests. Native, portable and firmware claims require their own gates.

Final offline JFFS2 builder receipts for RTIME/ZLIB/NONE each received a root
audit under `/data/cache/partmgr-jffs2-build-{rtime,zlib,none}-native-final/`.
All twenty-four image hashes, complete90,013-byte independent payloads, exact
symlink targets, enumeration-order image equality and tool/binary bindings
match. Each receipt has thirteen archived compiled source files. The engine
owner's final required formatting/Clippy/full host gates pass separately;
compressed owned editing and other codecs remain required.

Added APFS facade-to-builder-to-facade offline reauthoring coverage. It passes
the actual common facade tree to the native builder with two-entry pagination
and61-byte short target writes, verifies report SHA/length and reopened complete
clean allocation proof, and checks independent16,397-byte sparse data and8-byte
resource fork after dropping the destination facade. Both retained streams
reject changed source length at EOF and refund all leases. The focused test
and strict Clippy pass. This host integration test adds no native COW/recovery
or mounted macOS acceptance claim.

Root audited frozen APFS offline builder v12: sixteen exact source files and a
fixed binary copy are retained with matching hashes; generated image, complete
16,397-byte sparse payload, distinct copy and8-byte resource fork match native
tool outputs. Apfsck has empty diagnostics. Native checker/primary inode-name
evidence is accepted for this initial profile; pinned TSK4.14.0 drops two name
bytes when it decodes unhashed directory keys as hashed keys, so its fls output
is not a complete occurrence-name oracle. The engine owner completed required
fmt/strict Clippy/full locked host tests. New COW work remains separate.

Added examples/filesystem-apfs-copy.rs and docs/filesystem-apfs-copy.md for an
explicit volume/region common-facade capture with preflight, same-directory
temporary staging, exclusive bounded write session, complete report-bound
reopened audit, no-clobber publication and directory sync. Provisional actual
1,500-file CLI smoke/native extraction/collision-refusal evidence is retained
at `/data/cache/partmgr-apfs-cli-acew3jpz/receipt.json`. Exact immutable compiled-
source binding remains required before final CLI acceptance. An initial failed
memory preflight remains failed evidence; no source/destination mutation occurred.
Focused example/facade Clippy and current formatting pass. Agents are now
implementing compressed JFFS2 owned intent, native APFS COW and native JBD2
ownership/recovery primitives. Identity domains17/18 are reserved for the two
new owned sessions; immutable identities remain unchanged.

Root audited the final modern immutable ext receipt:
`/data/cache/partmgr-ext-modern-native-20261008-final/root-audit.json` verifies
seventeen archived source files,725 artifact hashes, six1/2/4KiB native cases
with complete131,089-byte independent payloads and three failing prerequisite/
existing-output controls. Later compact-map and owned-journal changes are outside
that frozen receipt.

Fixed excessive retained extent workspace: complete validation still reserves
the bounded temporary decode workspace, but returned files now keep a separately
precharged exact-size logical map and drop temporary references/buffers/lease.
The strengthened facade regression retains600 handles with a65536-unit ceiling
under64MiB, keeps retained reservations below1MiB, observes exactly600 payload
backend reads without metadata scans, and proves EOF cancellation/refunds.
Frozen modern-ext→ext2 CLI receipt
`/data/cache/partmgr-modern-ext-copy-78etehpo/receipt.json` independently verifies
all603 complete payload/name occurrences, actual shared alias inode/link count,
native clean destination, existing-destination refusal and334 unchanged compiled
snapshot files. Source metadata is explicitly transformed; native journal writes
and timing/firmware acceptance remain separate.

Frozen APFS CLI receipt
`/data/cache/partmgr-apfs-copy-frozen-q6i815vj/receipt.json` now binds the executed
binary to the same334-file immutable u0kw6ra0 source snapshot, replacing the
earlier provisional source-binding gap. Native checker has empty diagnostics;
complete16,397-byte sparse data and8-byte fork match the independent model.
Existing-output refusal preserves the image hash and source bytes are unchanged.
The complete independent occurrence-name oracle remains open. The frozen source
passes required formatting and strict all-target/all-feature locked Clippy;
full all-feature locked host tests are running in session43197 with log
`/data/cache/partmgr-pipeline-source-u0kw6ra0-host-tests.log`.

Session43197 subsequently failed in the new test-only compressed JFFS2 GC
proof: fs_jffs2_edit_compression_tests.rs:113 expected two relocated nodes but
observed six. The immutable u0kw6ra0 snapshot has no full host acceptance; its
passed formatting/Clippy and APFS/modern-ext native CLI receipts retain their
specific scopes. The compressed-edit owner is resolving the assertion against
the intended fragment/preservation contract. The earlier successful xjjwwhss
packaged checkpoint remains separate historical evidence.

The compressed-edit owner corrected the live GC proof test: reconstruction
retains five fragment boundaries, so relocation emits five data nodes plus a
final metadata node. The revised test checks all logical bytes and native
versions, including compressed selections/NONE fallback; its focused lib check
passes. This does not retroactively accept the failed immutable snapshot or
complete compressed owned-edit recovery/native gates.

Frozen focused ext/facade verification subsequently passes fs_ext,
fs_ext_extent, fs_ext_audit, fs_ext_tree, fs_ext_copy and fs_image. The retained
log is `/data/cache/partmgr-pipeline-source-u0kw6ra0-ext-tests.log`; all ordinary
cases pass and native prerequisites remain separate ignored gates. This checks
the compact-map change beyond its600-handle regression without replacing the
failed full-host result.

APFS copy pipeline now accepts optional GPT/MBR single-partition staging through
the shared destination helper. GPT uses the explicit Apple APFS type; both
schemes revalidate the exact type and extent after durable table commit, before
reopened filesystem audit and no-clobber publication. This implementation does
not establish macOS MBR recognition or firmware acceptance. Native partitioned
CLI evidence is being gathered separately from the accepted frozen standalone
receipt.

Frozen APFS standalone/GPT/MBR copy gate now passes at
`/data/cache/partmgr-apfs-partition-native-0_vidunu/receipt.json`:246 immutable
compiled sources,30 command logs, full independent16397-byte sparse payload and
8-byte resource fork per layout, native checker, independent reciprocal GPT
CRCs/type/extent or MBR0xaf entry, unchanged inputs and destination refusal.
The repeatable runner is `scripts/filesystem-native-apfs-copy.py`. Independent
full occurrence-name oracle/macOS/firmware remain open. Live GPT/MBR normal and
compressed QCOW2 conversion additionally passes exact restored logical equality
at `/data/cache/partmgr-apfs-{gpt,mbr}-container-smoke-asrabn82/receipt.json`;
filesystem interpretation through virtdisk is checked separately.

Root audit of test-only native JBD2 codec replay checkpoint
`/data/cache/partmgr-ext-jbd-codec-native-20261008-v2/root-audit.json` verifies231
artifact hashes and12 independent complete131089-byte payloads, ext3/ext4 at
1/2/4KiB with checksumv2/v3. This checkpoint does not prove owned journal
editing, torn bootstrap or interruption recovery.

Registry virtdisk0.2.0 normal/compressed QCOW2 APFS facade checks now pass for
both frozen GPT/MBR copy outputs. Integration test `apfs_read` compares every
66MiB logical disk byte, requires complete clean allocation proof, reads entire
16397-byte data/resource8 after facade drop, rejects cancelled empty EOF and
refunds leases. Consumer all-target strict Clippy passes in a frozen snapshot
with original fixture topology. Root receipts are
`/data/cache/partmgr-apfs-gpt-container-facade-native-v2-0_vidunu/root-audit.json`
and `/data/cache/partmgr-apfs-mbr-container-facade-native-0_vidunu/root-audit.json`.
The repeatable APFS CLI gate's missing-tools/existing-output controls pass at
`/data/cache/partmgr-apfs-copy-negative-ysap6189/receipt.json`, with no missing-tool
output created and existing marker unchanged.

Full required root checks pass on corrected frozen247-file snapshot
`/data/cache/partmgr-apfs-partition-check-source-b7s1t0it`: fmt, strict all-target
all-feature locked Clippy, and430 host tests (37 native/explicit gates ignored).
Receipt/log hashes are retained in
`/data/cache/partmgr-apfs-partition-native-0_vidunu/host-checks-with-fixtures.json`.
The original246-file build-only snapshot omitted the embedded exFAT binary
fixture and failed host compilation; its separate initial-host-checks.json
remains failed. The corrected snapshot preserves identical Rust/build sources
and adds that required fixture, without relabeling the failed archive. These
checks exclude subsequent agent recovery/semantic-negative drafts and do not
replace native or firmware gates.

Compressed owned JFFS2 range/recovery fuzz now runs both codecs and byte orders
from independent RTIME histories under bounded pool/scan/work/node/file/journal
limits. Instrumented counters prove strict recovery, mismatched decoder caps
and unknown codec in both rehashed v2 headers reject before writes, and exact
COMPLETE recovery is idempotent without writes. Full payload/hardlink identity
and refund checks follow reopen. All26 fuzz smokes and strict all-target fuzz
Clippy pass. Frozen instrumented JFFS2 campaign at
`/data/cache/partmgr-compressed-owned-fuzz-campaign-s67i1s17/root-audit.json`
verifies237 snapshot sources/222 bindings and1001 iterations0crashes0timeouts.
Root fmt passes; strict full root Clippy on the same snapshot fails unused
staged ext JBD bootstrap code with no caller yet. This failed full check remains
separate from accepted bounded campaign evidence. Native compressed editing,
exhaustive interruption scope and newer agent drafts require their own receipts.

The same237-file compressed-owned fuzz snapshot finishes438 ordinary root
host tests (38 explicit/native gates ignored); formatting passes. Its required
strict Clippy remains failed because staged ext JBD bootstrap implementation
was unused at capture. Retained scope/log/source hashes are in
`/data/cache/partmgr-compressed-owned-fuzz-source-s67i1s17-host-checks.json`.
This does not promote an incomplete full-check snapshot to accepted release
evidence or prove newer native recovery drafts.

Expanded all16-target frozen instrumented campaign passes1001 iterations per
target with zero crashes/timeouts at
`/data/cache/partmgr-compressed-owned-all-fuzz-campaign-s67i1s17/root-audit.json`:237
snapshot files/222 campaign bindings, every corpus seed and16 retained logs
verified. This refresh includes modern ext and compressed owned JFFS2
range/recovery, without promoting the failed strict-Clippy snapshot.

Root additionally verifies native JBD2 capsule checkpointsv4/v5 at
`/data/cache/partmgr-ext-jbd-codec-native-20261008-v{4,5}/root-audit.json`:257/259
artifact hashes and12 complete independent131089-byte payloads each. Thev5
test-only driver requires full borrowed final-redo overlay ownership audit
before native e2fsck home replay. Native capsule/preflight/replay compatibility
is demonstrated; owned editor/torn bootstrap/fault matrices/full operations
remain in development. A newer agent source checkpoint wires actual bootstrap
callers and reportedly passes strict Clippy; earlier immutable snapshots retain
their original failed check status.

Root APFS free-queue fuzz adds eight independent native seeds for IP/main ghost
and explicit retired extents plus rechecksummed counts/future-XID/overlap/domain/
current-owner/ghost-flag/free-bit negatives. Valid retirement blocks cannot appear
in free ranges; malformed/conflicting queues reject or suppress all free ranges.
All27 fuzz smokes/strict all-target fuzz Clippy and three focused queue tests
pass. Frozen instrumented APFS campaign
`/data/cache/partmgr-apfs-queue-fuzz-campaign-14w5ijjt/root-audit.json` verifies322
snapshot files,15 seeds and1001 iterations0crashes0timeouts. Full required root
fmt/strict Clippy/host checks pass on this same snapshot, retained at
`/data/cache/partmgr-apfs-queue-fuzz-source-14w5ijjt-host-checks.json`. Earlier
Clippy-failed snapshots retain their original status.

Owned APFS existing-length range/COW native-v5 is root-audited at
`/data/cache/partmgr-apfs-edit-native-v5/root-audit.json`:16 archived compiled
sources, fixed executable/tools,80 artifact hashes, clean native apfsck, full
16397-byte independent29-byte sparse-crossing patch/resource8 and primary
Unicode inode/link2. Cold recovery/interruption evidence is separate portable
editor tests; full namespace/resize/macOS/firmware remain required. The agent is
now extending the shared checkpoint assembler for all remaining namespace/file
operations, preserving this historical native checkpoint.

Owned JFFS2 compressed native range/GC/recovery checkpoint is root-audited at
`/data/cache/partmgr-jffs2-edit-codec-native-run4/root-audit.json`:23 archived
compiled sources/fixed binary/tools,118 artifact hashes,12 codec/endian/error
cases and24 full90346-byte native payload occurrences. Root independently
reconstructs initial90013-byte pattern,8193-byte range patch and333-byte ZERO
extension, checks alias/nested payloads, exact symlink/framing/erased victim,
native FF-name/CRC dump and four identical normal/recovered image groups. The
Jefferson parent/name query limitation remains explicit; historical native
shrinking-isize/kernel semantics, other codecs/NAND/hardware remain unfinished.
The freed agent is now implementing the missing owned JFS native-journal engine
under domain19, with borrowed metadata decode/audit and no mutable ReadAt bridge.

The APFS queue/compressed-owned JFFS2 checkpoint also passes extracted-package
checks at `/data/cache/partmgr-apfs-queue-package-14w5ijjt/root-audit.json`:
277 packaged files, 274 exact snapshot bindings, 67 retained test binaries and
six successful command logs. Normalized dependencies resolve from crates.io;
the original manifest is retained and verified. This excludes subsequent
APFS namespace, ext recovery and JFS editor drafts.

Raw/normal-QCOW2/compressed-QCOW2 read measurements now use the same selected
logical backend for file and direct modes, including container opening in
setup time. The xgu5kd03 frozen checkpoint passes 96 runs and all structural,
content and memory gates; its root audit is
`/data/cache/partmgr-container-read-bench-xgu5kd03/20261008T080923Z-2/root-audit.json`.
Required snapshot host checks pass (439 tests, 38 ignored). Controlled cache,
numeric timing thresholds, durable-write measurements and other profiles remain
unfinished, as specified in `filesystem-performance.md`.

Staged ext JBD2 v11 recovery has a root artifact audit at
`/data/cache/partmgr-ext-jbd-codec-native-20261008-v11/root-audit.json`:
20 archived sources, 335 artifact hashes and 111 successful native commands.
Twelve ext3/ext4 block-size/checksum cases each pass native journal replay and
read-only native checking after our bounded recovery, with 24 independent
complete 131089-byte payload models and three negative gate controls. Native
diagnostics were inspected as well as exit statuses. This accepts the private
checkpoint helper evidence; public owned sessions and complete operations are
still being implemented.

The first JFS native codec run is explicitly unaccepted at
`/data/cache/partmgr-jfs-redo-codec-native-run1/root-audit.json`. Although the
checker exits zero and applies the requested UID777 inode line, its diagnostic
says `logredo failed (rc=-245)`. Partial application cannot establish successful
native replay. The retained run remains unchanged while the JFS agent corrects
the history/protocol and strengthens diagnostic checks. Public JFS editing and
recovery remain closed.

The ten retained three-payload GPT/MBR copy profiles now pass twenty independent
normal/compressed QCOW2 conversions. Repeat with
`python3 scripts/filesystem-partition-container-check.py NATIVE_RECEIPT --output NEW_DIRECTORY`.
Each complete restored disk and bounded volume matches the original native
checkpoint. Root evidence at
`/data/cache/partmgr-partition-containers-cn9vngmd/root-audit.json`
checks 110 native converter commands and 323 hash bindings. Failed native
receipts, changed disks and escaping labels produce no output; an existing
output remains intact. This completes conversion evidence for these FAT12/16/32,
exFAT and classic-ext2 copies. Common-facade traversal is verified separately
below; writable operations and firmware remain separate gates.

Corrected JFS codec run2 passes root inspection at
`/data/cache/partmgr-jfs-redo-codec-native-run2/root-audit.json`.
A native mount-style fresh zero-sync marker precedes the transaction, avoiding
the formatter-history traversal failure observed in run1. Root verifies seven
archived sources, the fixed binary/tools/image, diagnostic-clean native replay
and exact equality between the journal's 128-byte inode after-image and the
replayed home line (inode2, UID777). Run1 remains unaccepted. This establishes
the staged native codec fixture only; our owned publication, restart recovery
and complete JFS operations remain required.

The common-facade gate now passes all twenty converted partition images and
sixty complete payload comparisons. Root evidence is
`/data/cache/partmgr-partition-read-native-tt2q4_ni-v3/root-audit.json`;
334 retained source files bind the fixed executable. Registry virtdisk0.2.0
matches each complete logical disk, then the bounded region passes a complete
clean allocation audit. Exact native names select all three streams; 73-byte
reads after dropping the facade match independent models. EOF cancellation and
final shared-budget refunds pass for every case. Missing-input and existing-
evidence controls fail explicitly and preserve the marker. The storage consumer
passes fmt, strict all-target/all-feature locked Clippy and full locked host
tests (9 passed, 6 opt-in gates ignored). The original copied executable lacked
its execution bit; that failed invocation is retained separately, and v3 uses
the corrected fixed executable. This extends immutable container pipeline
coverage without claiming edits, timing, faithful metadata capture or boot.

APFS namespace/data native-v3 now has a root audit at
`/data/cache/partmgr-apfs-edit-namespace-native-v3/root-audit.json`.
Thirteen operation cases bind seventeen archived compiled sources and 1054
artifact hashes. Root independently compares twenty-five full native stream
models, primary inode/link checks and removed-inode rejection; all native
allocation checks exit zero without diagnostics. Every case includes durably
torn block-zero publication-hint recovery using its retained anchor. Informational
apfsck version probes exit1; actual checker invocations pass. Portable cut-test
archive verification and full current host checks remain separate; an initial
host compile failure from an in-flight ext test is retained unchanged.

The v3 boot-fault scope is narrower than checksum-invalid-boot recovery: its
2048-byte durable prefix may already include every changed NX field. Thus v3
proves a reported partial boot write, cold reopen and final native validation,
but does not independently prove that the intermediate boot checksum is invalid.
The APFS agent is refreshing this gate with a 31-byte prefix and retained
independent pre-recovery checksum/native rejection. The original v3 artifacts
remain unchanged, with the limitation added to its root audit.

Ext JBD2 v14 adds a private native transaction lifecycle controller to the
earlier recovery helper. Root audit at
`/data/cache/partmgr-ext-jbd-codec-native-20261008-v14/root-audit.json`
verifies twenty-one archived sources, 339 hashes, eleven fixed-executable
ordinary tests and twelve independently checked native replay/our-recovery
cases with twenty-four full payload models. The owned public session,
source/generation handles and allocation/namespace operation set remain
unfinished; staged controller evidence does not satisfy those release gates.

APFS fuzzing now reaches the borrowed owned preparation/identity path and
checks zero mutation/barriers, stale identities, cancellation, exact unchanged
target bytes and pool refunds. A positive independent seed test prevents a
reject-all harness. Frozen358-file evidence
`/data/cache/partmgr-apfs-owned-fuzz-campaign-xjpdc0zh/root-audit.json`
passes1001 instrumented iterations with15 seeds/no crashes/no timeouts and
all28 ordinary fuzz smoke tests plus strict fuzz Clippy. Commit/recovery mutation
fuzzing remains open. The initial insufficient-work-allowance snapshot is
retained as failed; the successful campaign uses a new immutable snapshot.

Refreshed APFS native-v4 closes the invalid-boot evidence gap:
`/data/cache/partmgr-apfs-edit-namespace-native-v4/root-audit.json` checks
thirteen saved4096-byte boot blocks with independently calculated Fletcher
mismatches and thirteen native pre-recovery rejections. Cold anchored recovery
then passes clean native checking and twenty-five complete stream models,
with1131 artifact hashes. Native-v3 retains its narrower partial-write scope.

Portable APFS cuts also have a separate root audit:
`/data/cache/partmgr-apfs-edit-namespace-portable-cuts-v2/root-audit.json`
binds fourteen compiled sources, the fixed executable and successful log.
Twelve operations cover1608 scenarios under four modeled write/failed-flush
persistence combinations, comparing complete exact old/new signatures after
recovery. Physical power loss and macOS acceptance remain unproved. Full host
checks are separate. Repeated transactions with existing retirement queues,
broader trees and eventual safe reclamation remain required work.

The358-file21p8_tv6 frozen namespace checkpoint passes required root checks:
453 host tests,40 opt-in gates ignored, fmt and strict all-target/all-feature
locked Clippy. Exact source/log bindings are retained at
`/data/cache/partmgr-namespace-check-source-21p8_tv6-host-checks.json`.
Its extracted-package gate also passes at
`/data/cache/partmgr-namespace-package-21p8_tv6/root-audit.json`:
283 packaged files,280 exact snapshot matches,69 retained test executables,
six successful commands and registry-only normalized dependencies. This binds
APFS namespace/owned preparation fuzz and the staged ext/JFS journal checkpoint;
later shared indexed-read extraction and repeated APFS transactions are outside
this freeze. Host/package success does not establish portable targets, native
OS/firmware or timing qualification, or complete the remaining engine scope.

Partition conversion preflight now binds the native receipt hash to the exact
bytes parsed and rejects receipt changes before creating output. A deterministic
mutation during disk hashing rejects with exit2/no output at
`/data/cache/partmgr-receipt-preflight-race-8gypms4o/evidence.json`.
The corrected gate also passes all ten original profiles/twenty conversions at
`/data/cache/partmgr-partition-container-receipt-bound-v2/receipt.json`.
Earlier conversion receipts retain their original gate/source scope.

Container pipeline coverage now derives each filesystem region from actual
`partmgr::layout::DiskLayout::inspect` of the registry virtdisk logical reader,
checks GPT/MBR scheme and exact fixture bounds, then opens the bounded facade.
All20 normal/compressed cases and60 payload models pass at
`/data/cache/partmgr-partition-inspect-native-du_c8iau/root-audit.json`.
The334-file frozen storage consumer passes formatting, strict all-target Clippy
and full locked host tests; earlier fixed-offset evidence remains unchanged.

Private JFS owned UID publication/recovery now has a root audit at
`/data/cache/partmgr-jfs-owned-uid-native-run2/root-audit.json`.
Eleven compiled sources and49 artifact hashes bind three normal/home-error/
recovery-error cases, identical complete final images, exact UID/link fields
and unchanged bytes outside declared inode/header/log ranges. Both independently
replayed interrupted copies have clean native diagnostics; final checks are
read-only and clean. This remains a bootstrap transaction checkpoint, excluding
the full persistence matrix, torn bootstrap, range/allocation/namespace operations
and public writable acceptance.

The shared ext indexed-read extraction is independently rechecked at
`/data/cache/partmgr-ext-modern-native-20261008-indexed-final/root-audit.json`:
17 exact sources,751 artifact hashes,six complete native payload models and
three fatal gate controls. All45 native commands succeed; the immutable public
reader scope is preserved. Private owned range/session evidence at
`/data/cache/partmgr-ext-jbd-codec-native-20261008-v17/root-audit.json` binds
22 sources,353 artifact hashes and111 native commands. Twelve native journal
replays preserve the original payload; twelve owned recovered payloads match
the independently reconstructed 64-byte change at offset37. Twelve ordinary
JBD tests include repeated indexed reads with no metadata rescan and no backend
I/O for EOF/empty reads. Public owned allocation and namespace editing remain
unfinished; these receipts do not complete writable ext acceptance.

Pipeline5 now has partitioned APFS range evidence at
`/data/cache/partmgr-apfs-writer-native-v3-1f5uggh5/root-audit.json`.
The363-file frozen consumer uses registry virtdisk0.2.0, actual GPT/MBR
inspection and exclusive bounded raw/QCOW2 writers. Eight cases cover normal
publication and cold recovery from a durably saved96-byte anchor after an
actual31-byte boot-hint write. Root independently confirms four checksum-invalid
intermediate boot blocks, sixteen full native DATA/resource-fork models, four
identical normal/recovered whole-image pairs, unchanged partition framing,
48 native command results and190 artifact hashes. Two fatal gate controls
preserve an existing destination and reject missing input before output creation.
The input is a native-checked three-file copy; the earlier1501-file/multi-leaf
attempt is retained as failed evidence. Writable multi-leaf support, repeated
container transactions, reclamation and hardware/firmware correctness remain
required. Per-case stage reports distinguish partition, container, filesystem,
recovery, copy and untested boot outcomes.

The frozen storage consumer passes formatting, all-target/all-feature locked
strict Clippy and all-feature locked host tests. Its check logs are bound in
`/data/cache/partmgr-apfs-writer-source-v3-1f5uggh5-checks.json`.
Independent repeated native APFS publication is audited at
`/data/cache/partmgr-apfs-repeat-native-v7/root-audit.json`: twenty exact compiled
sources, forty artifact hashes, five ordinary tests and two full native payload
models. Genuine expanded descriptor/data rings retain XID2 retirement ownership
through XID3; the native single-chunk internal pool remains exactly six blocks.
A third transaction is refused before writes. Arbitrarily enlarged-pool attempts
are retained as failures. This strengthens repeated publication evidence without
claiming reclamation or multi-chunk/multi-leaf editing.
