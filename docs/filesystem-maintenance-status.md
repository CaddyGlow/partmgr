# Filesystem maintenance implementation inventory

Inventory date: 2026-10-13. Implements the inventory portion of P0 in the
[maintenance plan](filesystem-write-maintenance-plan.md). This is a source
inventory and evidence index, not acceptance of P0 or any later milestone.
Public APIs must be checked against the final integrated source before release.

## Added maintenance foundation

`fs_maintenance` provides separate `MaintenanceOperation` and
`MaintenanceCapabilities` queries, a versioned per-feature `FeatureManifest`,
source/region/geometry/metadata `PlanBinding`, borrowed `CheckReport` findings,
and native `MetadataPatch` requests. Missing or duplicate capability entries,
foreign-profile/backend evidence and unknown manifest versions cannot establish
qualified support. Evidence records bind a receipt location and SHA-256; callers
must still verify the artifact and implementation revision.

`FieldPatch::Unchanged`, `Set` and `Remove` distinguish preservation, setting an
empty/zero value and removal. Timestamp validation rejects missing epoch/zero
resolution; native ranges, view selection, inheritance, privilege and journal
semantics remain engine work. These request types execute no mutation.

`fs_maintenance_audit::check_ext` and `check_ntfs` retain typed native audit
evidence and its resource reservation. They compare native geometry with the
supplied binding; identities, generations and digests remain caller-established
context rather than authenticated facts. The summaries explicitly skip checks
outside the existing engines and therefore never claim a complete clean
maintenance check. Limits, cancellation, unsupported profiles and I/O failures
remain distinct. The additive native `audit_detailed` and `audit_ntfs_detailed`
APIs now retain findings, counters and resource reservations after later scan
failures. Their incomplete reports withhold clean and free-space proof; legacy
`Result<Report, Error>` entry points preserve their original discard behavior.
The maintenance adapters retain both partial native evidence and the original
failure, including any previously observed NTFS recovery obligation.

The [bounded LZNT1 read profile](filesystem-ntfs-compression.md) uses published
`ms-compress` for explicit compressed-stream reads, including mixed raw/zero
units and fragmented/segmented allocation. This is a portable decoding
foundation; native Windows compression qualification and writes remain open.

The additive `audit_ntfs_resolved`/`audit_ntfs_resolved_detailed` profile and
`check_ntfs_resolved` bridge audit bounded ATTRIBUTE_LIST extensions, plain/sparse
segmented native allocation and resolved directory indexes. Physical claims keep
base ownership, carrying FILE record/sequence, attribute offset/instance and VCN
provenance, including allocation beyond EOF/initialized size. Orphan extensions
cannot establish complete ownership or free-space proof. `directory_resolved`
also accepts initialized nonsparse nonresident `$I30` bitmaps. Strict audit and
directory APIs retain their earlier profile. Compressed/encrypted ownership,
split ATTRIBUTE_LIST values, recovery and complete system/security semantics
remain excluded; this does not complete N1 or qualify mutation.

Fresh Linux native-tool evidence for this resolved profile is retained at
`/data/cache/partmgr-maintenance-resolved-native-20261010-v1/qualification.json`
(SHA-256 `93d084fca5e04caeac52af0505f2df65f1116b0ee92d339476fc4ffa59fe90a1`).
Two previously independently authored fixtures match native `ntfsinfo` cluster/
free counts and complete `ntfscat` live/extension FILE counts: split MFT has
21 live FILEs/1 extension and 637 allocated clusters; the ADS fixture has
34 live FILEs/14 extensions and 676 allocated clusters. Both contain 16,383
clusters and produce complete defect-free ownership/namespace results.
The receipt binds its exact captured compiled sources, tools, image and binary hashes,
commands and full outputs; missing-image/source/tool and reused-destination
controls fail. The initial failed native attempt is retained. These counts do
not establish complete native stream/metadata equality, Windows correctness,
compressed/encrypted ownership, mutation or the full N1 corruption corpus.

`fs_ntfs_logfile` begins N2 with bounded immutable observations of both restart
copies, exact versions 1.1 and 2.0/4096-byte page/512-byte USA framing and the historical
single-client layout. It retains raw headers, individual failures and source
guards. `inspect_ntfs_logfile` resolves record 2's ordinary initialized stream;
`inspect_logfile_pages` and `inspect_ntfs_logfile_pages` add bounded physical
header inventory through direct and native-selected streams. Reports separate
physical scan completion, local framing and supported flags. Tail selection,
active LSN windows, record succession, transaction tables, redo/undo,
replay and native publication remain unimplemented. Unknown tail flags retain
framed fields with unsupported semantics. Physical-page inventory supports 2.0 with 32 fast-copy pages and ordinary pages
starting at page 34. Exact record queries support matching restart contexts or an
explicitly requested source-bound copy for versions 1.1 and 2.0. Divergent
restart copies remain ambiguous for authoritative selection, and erased pages do
not establish a clean recovery state. The
[pinned journal design](filesystem-ntfs-logfile-design.md) records exact scope.

The physical-page Windows-authored offline gate passed for its captured revision:
`/data/cache/partmgr-ntfs-windows-logfile-20261010-v1/volume-pages-v3-qualification.json`,
SHA-256 `c313f1bc3afb08f1f44321cea99c7ef02323fdfb5bbe94d26bfe79e98c124ee2`.
All 654 candidates matched between record 2 selection and the direct stream,
and matched independent Python header fields and protected page hashes:
2 tails, 54 ordinary RCRD pages and 598 all-`0xff` pages. Tail flags 3 remained
unsupported despite valid local framing. The adapter selected native record 2,
sequence 2, with volume flags 128 (dirty bit clear); independent source scopes
remained distinct. Offline raw restart headers are 1.1 despite mounted Windows
`fsutil` reporting 2.0. Seven missing-input/reused-destination controls failed.
Transaction analysis remains false. This establishes scoped restart inspection,
physical header equality and native stream selection, with no version 2.0,
active-log, recovery or writer qualification. The earlier restart-only and
direct-page receipts remain historical evidence for their bound source revisions;
failed earlier volume attempts and the final stable rebuild are retained.

Restart candidate ranking now owns both source-bound copies and requires an
explicit non-rollover numeric-ordering assumption. It checks compatible geometry
and client identity, compares complete fixed-up areas for equal-LSN ties, and
retains rejected-copy diagnostics. Backend, resource and final source failures
block fallback. A native-volume wrapper applies the same source guard. Nine
independently authored focused tests passed; authoritative active-tail discovery,
fast-copy overlays, rollover handling and native qualification remain open.
Formatting, all-feature Clippy and tests, no-default-feature Clippy and the
portable host test selection passed with unchanged source snapshots. The receipt
is `/data/cache/partmgr-maintenance-ntfs-restart-selection-checks-20261011-v2/result.json`.

Exact-LSN record inspection now assembles bounded immutable envelopes and payloads,
including synthetic multipage and circular-wrap cases. It requires matching restart
contexts or one explicit copy and exact client/LSN identity, retains page provenance
and source failures,
and exposes payload only after complete structural validation. Opaque page bit
`0x2` is retained with explicitly incomplete flag semantics; other unknown bits
remain unsupported. It selects no active window or transaction ordering.

Complete record reports now also expose an immutable physical extent: inclusive
final byte, containing page offset and actual physical wrap count. Empty payloads
end at the final LFS header byte; continuation page headers and alignment padding
are excluded. Failed final source/cancellation guards withhold the extent. This
structural observation does not identify a successor LSN or active-log membership.
Four independently authored extent tests cover both admitted log versions,
empty payloads, page boundaries, circular continuation, repeated first-page
visits and withheld partial/failing results. All five required host checks passed
with unchanged source snapshots at
`/data/cache/partmgr-maintenance-ntfs-record-extent-checks-20261011-v1/result.json`.

Source-owned bounded previous-LSN and undo-next-LSN observation loaders now retain
a chain of exact record reports in one explicit restart context, including raw
restart equality checks, charged cycle detection and aggregate query/page/payload/
work ceilings. Partial results retain the unresolved target, failed-query evidence
and original errors. Native-volume final guards suppress zero-link closure on
failure. Reaching zero is a structural observation, with no numeric chronology,
transaction-ID equality, complete-history, active-window or undo/replay claim.
Seven independently authored tests cover both versions, zero-link closure,
cycles, context/client failures, original I/O causes, aggregate limits and
cancellation/source changes. All five required host checks passed against
unchanged source snapshots at
`/data/cache/partmgr-maintenance-ntfs-record-links-checks-20261011-v1/result.json`.
Native qualification for this loader remains separate from the older record
receipts below.

The record gate passed for its captured source revision at
`/data/cache/partmgr-ntfs-windows-logfile-20261010-v1/records-v4-qualification.json`,
SHA-256 `c9e94eb0251e75a9b34b25996ed9bed8f8f2813bc33f6cb1cf8dd9ff6a31e6be`.
Two native single-page envelopes and payload hashes matched an independent Python
byte model through direct and volume-selected queries. Eight missing-input and
reused-destination controls failed as expected. This does not qualify native
multipage records, active-window selection, transaction analysis or recovery.
The preceding record milestone passed 55 focused restart/page/record tests, the
full all-feature host suite, all-feature and no-default-feature all-target Clippy,
and the CI portable host test selection. Commands and logs are retained in
`/data/cache/partmgr-maintenance-record-checks-20261011-v2/result.json`.
The dirty-capture restart gate also passed:
`/data/cache/partmgr-ntfs-windows-dirty-logfile-20261010-v1/restart-v2-qualification.json`,
SHA-256 `07986ec4c327b930f06eb5f19f400b051848162a6f129bb3b0dfcd6a60254e93`.
It binds the frozen Windows power-cut capture, validates both 2.0 restart copies
with LSNs 4753128 and 4839042 and flags zero, and compares native stream selection.
Six missing-input/reused-output controls failed. Final formatting and all-target
all-feature Clippy passed, including the new dirty gate; logs are in
`/data/cache/partmgr-maintenance-final-gates-20261011-v2/`. At that captured revision, 2.0 record queries remained unsupported. Subsequent
physical-page and explicit-context extensions are qualified separately below;
no recovery or active-window claim follows.
An independent recovery-copy image was prepared, but the recovery VM launch was
aborted while awaiting approval, so native recovery and post-recovery inventory
have not run. The frozen pre-recovery capture remains unchanged.

The version-2.0 physical-page gate passed:
`/data/cache/partmgr-ntfs-windows-dirty-logfile-20261010-v1/pages-v2-qualification.json`,
SHA-256 `477de6c7d184847b4eb78e4600d9c204ac2307c169b561316e7916acd477479f`.
All 654 candidates match independent protected/fixed-up hashes and header fields,
plus the complete native-selected inventory: 32 fast RCRD pages, 494 ordinary
RCRD pages and 128 erased pages. Five ordinary pages retain flag 3 with unsupported
semantics. Fast destinations have explicit alignment/range validation coverage;
duplicate destinations stay independent. Seven missing-input/reused-output
controls failed. The clean 1.1 record gate was rerun against the changed source.
The 61 focused journal tests, formatting, all-feature all-target Clippy, full
all-feature host suite, no-default-feature all-target Clippy and CI portable host
test selection passed. Source hashes remained unchanged throughout these checks.
Commands, exits and durable logs are under
`/data/cache/partmgr-maintenance-two-zero-pages-checks-20261011-v1/`.

Explicit restart-context queries now assemble both dirty 2.0 checkpoint records
without selecting a newest copy or applying fast copies. Unselected completed
format failures remain diagnostic; backend I/O, cancellation and resource failures
still block completion. The borrowed NTFS client restart decoder reads the 64-byte
version-1.0 prefix and length-gated extensions through 112 bytes, preserving raw,
partial, reserved and trailing bytes. The client payload version is independent
of LFS version, and referenced tables remain unvalidated.

The current dirty-context/checkpoint gate passed:
`/data/cache/partmgr-ntfs-windows-dirty-logfile-20261010-v1/contexts-v3-qualification.json`,
SHA-256 `e9a70d721b154cab37e0dca5199a41074e59ecbe2a12017dd6109352fd5631aa`.
Both native envelopes, 112-byte payload hashes, and checkpoint fields match the
independent models through direct and native-selected queries. Nine missing-input
and reused-output controls failed. The clean 1.1 compatibility gate passed at
`/data/cache/partmgr-ntfs-windows-logfile-20261010-v1/records-v7-qualification.json`,
SHA-256 `bbb0ebc74d435466db4c9aba71cb05284e58c454b5e3823553458d55b9627819`.
The 72 focused tests, formatting, all-feature all-target Clippy, full all-feature
host suite, no-default-feature all-target Clippy and CI portable host test
selection passed. Source hashes stayed unchanged throughout verification.
Commands, exits and logs are under
`/data/cache/partmgr-maintenance-context-checkpoint-checks-20261011-v2/`.
A subsequent module-comment correction changed no runtime code; formatting and
both source-bound native gates were rerun for that final revision.

The six independently captured table-anchor records use envelope flags 4 or 5,
which remain unsupported by the production query profile. Their raw payloads and
redo regions are preserved at
`/data/cache/partmgr-ntfs-windows-dirty-logfile-20261010-v1/tableanchors-v1/receipt.json`.
They establish the next admission gap, not table validity or replay support.

No repair, formatter, filesystem grower, journal lifecycle manager or native
metadata writer is added. Existing builders/editors retain their prior scope.

Validation for the physical-page extension: repository formatting,
all-target/all-feature Clippy with warnings denied, and 36 focused journal tests
passed. The full all-feature host suite, no-default-feature all-target Clippy and
the CI no-default-feature host test selection also passed for this extension.
The full suite log is `/data/cache/partmgr-maintenance-host-tests-20261010-pages-v3.log`;
portable commands, exits and source hashes are retained in
`/data/cache/partmgr-maintenance-portable-pages-20261010-v1/result.json`. The bare-metal
`x86_64-unknown-none` build could not run because the configured shared toolchain
lacks that target's `core`. The scoped Windows journal-inspection receipt above
does not establish mounted filesystem mutation, power-loss recovery or firmware
acceptance.

Native evidence availability at the current continuation: the previously recorded
`/data/cache/partmgr-*` fixture, specification and qualification directories are
absent, and reasonable searches of `/data/cache`, `/tmp` and local project/cache paths
found no relocated input images. Historical URI/hash entries above identify prior
receipts but cannot currently be reverified from those locations. Pinned Linux
and dfir sources were reacquired separately under
`/data/cache/partmgr-maintenance-reacquired-specs-20261011-v1/`. New client-record
and table work must remain without renewed native qualification until the original
fixture inputs are recovered or a separately acquired corpus is qualified.

The current additive client-record view borrows validated type-one payloads,
checks redo/undo and LCN framing, and preserves unknown operations and raw bytes.
Generic restart-table inspection admits dump operations 29, 31 and 32 and checks
slot extents, allocation markers and complete bounded free-chain membership.
Independent byte, entry, work and cancellation limits apply without allocation.
Accessors derive bounds from immutable framing even when public observations are
edited. Opaque LFS envelope bit 4 is retained without claiming its meaning.
The six focused logfile suites contain 90 passing synthetic tests. These additions
do not qualify table entry bodies, checkpoint-reference correlation, active-window
selection, redo/undo execution or a native writer. In particular, generic empty
tables and non-word-sized slots are structural observations, not qualified native
dump profiles.

For this client/table extension, formatting, all-target/all-feature Clippy with
warnings denied, the complete all-feature host suite, no-default-feature
all-target Clippy and the CI portable host test selection all passed. Logs and
an unchanged source snapshot are indexed at
`/data/cache/partmgr-maintenance-client-table-checks-20261011-v1/result.json`.
This validation does not renew the unavailable native fixture qualification.

The source-owned checkpoint dump loader now follows all nonzero-byte references
from one immutable source and explicit restart copy. It checks expected dump
operations and restart-context stability, retains earlier and failed record
evidence, and exposes reference-length equality as an observation. Aggregate
queries, restart/candidate pages, reserved payload bytes and work are bounded.
Zero-byte references are skipped independently of their LSN. A separate
`references_available()` marker distinguishes decoded empty references from
placeholders after checkpoint decoding fails. The native-volume adapter retains
record-2 ownership and independent volume flags and checks the underlying volume
again after loading. Names bodies, typed entries, active membership and replay
remain unqualified.

The extended dirty native gate compares six explicit table-anchor payloads and
redo hashes against a separate Python inventory and exercises the direct/native
loaders. Its source capture now includes the new client/table/loader modules.
The extended gate has only been compiled; missing original fixture inputs prevent
renewed native execution evidence.

Eleven focused loader tests pass, including partial failures, aggregate budgets,
unavailable references, changed restart bytes and native-volume source guards.
Formatting, all-feature/all-target Clippy, the complete all-feature host suite,
portable all-target Clippy and the CI portable host test selection pass; logs and
source hashes are indexed at
`/data/cache/partmgr-maintenance-checkpoint-loader-checks-20261011-v3/result.json`.
A subsequent native-gate-only correction compares native owner key/generation
while preserving distinct source scopes. Formatting, all-feature Clippy and both
native gate builds pass after that correction; the exact amendment and unchanged
production source hashes are recorded in `final-gate-amendment.json` beside the
result. Fixture-dependent tests remain ignored, not native execution passes.

Typed NTFS checkpoint entry views now borrow allocated open-attribute, dirty-page
and transaction slots from the source-owned report. They check version-specific
prefixes and variable LCN bounds, preserve opaque pointer/reserved/tail bytes and
retain unknown transaction states. Eight independent synthetic tests pass.
Seven additional independent synthetic tests pass for the report's join of
immutable dirty-page target offsets to allocated
open-attribute slots within the same checkpoint context, validating alignment,
bounds and allocation. This does not establish FILE ownership or transaction
chronology. Native gate source captures include the new entry module; renewed
Windows execution evidence remains unavailable.

E1 now has a separate private foreign JBD preflight using native scan semantics
without an owned preparation or legacy integrity footer. It validates the original
active header before virtual normalization, audits the complete final-redo overlay
and immutable journal mapping, retains exclusive source-bound evidence and checks
controls/length/cancellation without writes. Six synthetic tests cover footer-free
commits, bad CRC/geometry, denied destinations and ownership, phase budgets,
cancellation, final-read source changes, sequence rollover and active empty logs.
The first unconsumed scanner ID and the fresh post-recovery restart ID are separate;
the latter skips one ID to invalidate stale commits.

A fresh independent e2fsprogs oracle recovered three manually authored footer-free
ext3 fixtures at 1/2/4 KiB, preserving committed superblock markers and complete
file payloads. Receipt
`/data/cache/partmgr-ext-foreign-preflight-oracle-20261011-v3/receipt.json`
(SHA-256 `d41db945ad24e9fe013fca1a6b0b69e826e03d358eaf8d9f28b491fa730a83de`)
captures the oracle source, native tools, 36 commands and 98 artifact hashes.
Missing-tool and reused-output controls fail closed and preserve all original
fixture bytes; their result is at
`/data/cache/partmgr-ext-foreign-preflight-controls-20261011-v1/result.json`.
The partmgr preflight now passes against all three images, verifying full redo
bytes, clean overlay audits, journal mapping, sequence boundaries and zero writes.
The exact compiled source, binary and corpus are archived at
`/data/cache/partmgr-ext-foreign-native-20261011-v1`. A separate runner passed the
positive test and five missing-input/reused-output controls; its receipt is
`/data/cache/partmgr-ext-foreign-qualification-20261011-v1/qualification.json`.
Kernel-authored dirty journals, native recovery interruption evidence and public
E1 qualification remain required gates.

A private checksumless foreign recovery writer now preflights the same mutable
storage capability, persists and reads back all replayed home blocks before
publishing an empty journal, and clears only the filesystem recovery flag byte
last. It excludes stale sequence IDs across the complete journal before staged
sequence/start publication; ambiguous first-record states require exact alternate
replay/home equality or refuse before writes. Nine recovery and six preflight synthetic tests cover modeled
write/flush cuts, prefix tears, rollover and stale records, volatile persistence,
short writes, readback failure, cancellation, budgets and clean retry. The native
comparison gate produces complete images identical to independent e2fsprogs
recovery at 1/2/4 KiB; its passing positive/rejection receipt is
`/data/cache/partmgr-ext-foreign-recovery-qualification-20261011-v1/qualification.json`.
Storage does not guarantee atomic sector writes: torn checksummed journal headers
still need an additional recovery protocol. This private profile requires journal
first block one and checksumless filesystem controls. Native crash interruption
and kernel-authored fixtures remain required before widening admission.
The recovery writer additionally preserves the raw group-zero inode-table
pointer, including its high word for 64-byte descriptors; a clean final-state
counterexample shows why journal inode/map equality is insufficient for torn
relocation. The new modeled native-cut matrix comprises 374 fault cases,
21 distinct persisted images and 84 native commands across 1/2/4 KiB. Native
sequence 3/4 is independently checked while Rust retains restart sequence 3;
fixed `E2FSCK_TIME` timestamps are compared without masking. Final qualification
passed at
`/data/cache/partmgr-ext-foreign-native-cuts-20261011-v3/qualification.json`.
All five required host checks passed against unchanged source snapshots at
`/data/cache/partmgr-maintenance-foreign-native-cuts-checks-20261011-v2/result.json`.
The verifier also rejected a consistently rehashed image/manifest sequence
forgery at
`/data/cache/partmgr-ext-foreign-sequence-forgery-control-20261011-v1/result.json`.
This does not close kernel-authored dirty fixtures, mount/crash/hardware,
checksum-v2/v3 foreign publication or public-session promotion gates.
NTFS FILE-reference joins likewise remain current-home observations until an
authoritative replay overlay resolves pending metadata changes; missing names or
extension membership must not be guessed from attribute type alone.

After the native restart-sequence correction, formatting, all-target/all-feature
Clippy with warnings denied, the complete all-feature host suite, portable
all-target Clippy and the CI portable host test selection all pass. The unchanged
compiled-source snapshot and full logs are archived under
`/data/cache/partmgr-maintenance-entries-foreign-checks-20261011-v2/result.json`.
The earlier v1 checks remain retained before that evidence-driven correction.
These checks do not substitute for Windows, kernel-authored dirty-log, recovery
write, interruption or firmware gates.

After adding the source-owned dirty/open join and native foreign-preflight gate,
all five required host/portable checks pass again. Logs, hashes and the unchanged
compiled-source snapshot are retained at
`/data/cache/partmgr-maintenance-links-native-checks-20261011-v1/result.json`.

After adding private foreign recovery and its full-image native comparison gate,
formatting, all-feature Clippy/tests and both portable checks pass again. The
unchanged compiled-source archive and logs are retained at
`/data/cache/partmgr-maintenance-foreign-recovery-checks-20261011-v1/result.json`.

## Existing foundations

The std-only `fs_maintenance_format` adapter now owns fresh classic ext2 working
files and binds empty-root plans through an exclusive owner borrow. It scans the
actual bounded zero output before emission, verifies and audits the result, and
permits artifact extraction only after success. Existing files and symlinks are
never adopted; failed sessions are terminal. Eleven private tests include 1,260
interruption cases across all three block sizes; the public three-block-size test
also passed. The release-mode e2fsprogs gate passed on three fresh 16 MiB images,
including exact native fields, counts, root metadata and empty namespace, with
five rejecting controls and 703 verified artifact hashes. Receipts are
`/data/cache/partmgr-ext-format-native-20261011-v2/qualification.json` and
`/data/cache/partmgr-ext-format-release-binding-20261011-v2/result.json`.
Formatting, all-feature Clippy/tests, no-default-feature Clippy and portable host
tests passed with unchanged source snapshots. The receipt is
`/data/cache/partmgr-maintenance-ext-format-checks-20261011-v2/result.json`.
See [the formatting contract](filesystem-ext-format.md).
This does not implement ext3/ext4 formatting, existing-volume erasure or growth.

Classic ext2 growth within the existing final block group is implemented
through `ExtEditor::plan_grow_filesystem`. It plans actual bitmap and native
primary/backup geometry changes inside an already large enough owned region,
using the existing external undo protocol. Seven independent host tests and
6,144 cold-recovery cut cases pass. The release gate passes on independently
populated native 1/2/4 KiB images, with exact bitmap/counter/canary checks,
e2fsprogs consistency, unchanged payload and metadata, and four rejecting
controls. All five host checks pass with unchanged source snapshots. Receipts
are `/data/cache/partmgr-ext-grow-release-binding-20261011-v1/result.json` and
`/data/cache/partmgr-maintenance-ext-grow-checks-20261011-v2/result.json`.
Mounted use, native crash recovery, native allocation after growth, new groups
and ext3/ext4 growth remain open. See [the growth contract](filesystem-ext-grow.md).

The 2026-10-11 Windows fixture reacquisition did not launch a guest: the sandbox
rejected writing the immutable base's lock file, and the required elevated retry
was aborted. No native evidence was generated or historical receipt replaced.
The terminal launch result and unchanged disposable disk identity are retained at
`/data/cache/partmgr-ntfs-windows-logfile-reacquire-20261011-v1/acquisition-result.json`.

The public exports in `src/lib.rs` distinguish the following foundations.
Existing builders and editors are profile-specific; none implies family-wide
repair, formatting, geometry growth, ACL mutation or journal lifecycle support.

| Area | Public foundation | Remaining maintenance boundary |
| --- | --- | --- |
| Storage | `fs_storage`, `fs_undo`, `fs_pipeline`, `storage`, `editor` | Bind maintenance proposals to exact owner/generation/geometry; distinguish filesystem growth from partition changes and file-length edits |
| FAT/exFAT | Readers, ownership audits, builders, owned editors | Dedicated check/repair/format/grow qualification; native timestamp and metadata policies; no standard native ACL |
| ext2 | `fs_ext_builder`, `fs_ext_edit`, `fs_ext_audit`, `fs_maintenance_format`, tree/copy access | Fresh empty formatting and growth within the existing final group have scoped classic e2fsprogs and host fault evidence; new groups, mounted/native crash and allocation-after-grow gates, repair and ACL editing remain open; external undo remains distinct from native journal editing |
| ext3/ext4 | `fs_ext` immutable profiles, audits and capture | Std manifest-seven integrates symlink lifecycle alongside classic append/create/truncate/write_at/extend_sparse and hardlink/namespace API; all five manifest-seven host checks pass; source-bound native interruption/recovery, adversarial controls and final rehash pass for the archived manifest-seven snapshot; archived manifest-six sparse host/native/adversarial qualification passed; modern mutation remains gated |
| NTFS | `fs_ntfs`, `fs_ntfs_audit`, `fs_ntfs_metadata`, `fs_ntfs_security`, `fs_ntfs_tree`, USN decoding/extraction | No public NTFS native transaction writer, formatter, geometry grower or repair engine |
| HFS/HFS+/HFSX | Readers/audits/trees; HFS+ builder | Native maintenance and macOS qualification remain separate |
| APFS | Readers/audits/trees, bounded builder and owned COW editor | Broader topology, macOS and independent maintenance operations remain gated |
| JFFS2 | Logical-NOR readers/audits/builders/owned append editor | Physical flash, NAND/OOB/ECC, mounted semantics and geometry growth require separate evidence |
| XFS/JFS | Readers/audits/trees | Writable log, formatter, repair and grow admission remain gated |
| UDF/ISO9660 | Optical adapters and staged authoring through integration dependencies | Rebuild/new-session output is distinct from in-place repair/grow |

The `std` public `fs_ext::ExtJournalSession` now declares profile manifest
version seven. Its filesystem allowlist is unchanged: Linux revision one,
128-byte inodes, 1/2/4 KiB blocks, feature words 4/2/1 with transient RECOVER,
and an internal checksumless journal without REVOKE and first block one.
Alongside ordered regular-file append/create/truncate, `write_at` and `extend_sparse`, it exposes `create_directory`,
`rename`, `hard_link`, `unlink_file`, `remove_directory`, `create_symlink`,
`replace_symlink_target`, `unlink_symlink` and `read_symlink`. The manifest-seven
symlink integration passes all five source-bound host checks; source-bound native interruption/recovery, adversarial controls and final rehash pass for the archived manifest-seven snapshot. Names are exact bytes; creation
uses explicit native metadata. Rename refuses existing destinations and cycles.
Deletion requires explicit native time, nonzero and at least the inode count;
source-owned planner kind guards distinguish regular unlink from empty-directory
removal before publication. No recursive deletion or payload wiping is implied.
Successful mutation/recovery invalidates handles; errors can conservatively
retain `NeedsRecovery`. Physical controller and planner authority remain private.
File handles and reads remain owner/generation bound. Explicit recovery checks
the replayed profile before writes and retains recovery state through final
profile/source/cancellation checks. Foreign logs are not an automatic fallback;
the caller must maintain exclusive backend access.

All five public-session host checks pass at
`/data/cache/partmgr-maintenance-ext-public-session-checks-20261011-v2/result.json`,
including six public consumer tests. Public ordered v2 and renewed private
fulljournal v10 native gates pass for their bound source snapshot. Historical
private receipts retain their original scope. Broader ordered operations,
modern profiles, metadata/ACL editing and the complete maintenance plan remain
unfinished; E1 is not declared complete.

The private owned session now has bounded cold admission that retains
`NeedsRecovery` until explicit recovery, a fresh complete ownership audit and
final source/cancellation guards succeed. Backend failures cannot select a
different initial recovery path merely through their error kind. Fresh classic
ext3 evidence is retained at
`/data/cache/partmgr-ext-owned-release-binding-20261011-v10/result.json`:
1,320 modeled extension write/flush cuts, 121 distinct persisted images,
1/2/4 KiB blocks and 128-byte inodes. Independent native replay and cold owned
retry match every home byte, excluding only journal data. Repeated replacement,
rename, truncate, create and delete receive separate native image checks.
The source-bound optimized gate retains 817 commands and rejects missing/stale
sources, reused output and an altered verifier. This does not establish mounted
or hardware crash correctness, modern profiles, complete operation interruption
coverage, metadata/ACL editing or broader public operations. See
[the scoped ext journal evidence](filesystem-ext-journal-edit.md).

Classic create/extend planning retains source-bound private ordered-data roles,
checked against original allocation and the final regular-file mapping. The
private ordered controller now consumes that sealed evidence for regular-file
append and creation. It completes combined ownership and publication preflight
before writes, durably establishes preparation/activation/recovery controls,
writes and flushes exact data ranges, verifies their complete containing blocks,
and then publishes metadata-only mutation redo. Existing EOF writes preserve the
old visible prefix; directory and indirect blocks remain metadata. The existing
fulljournal path remains separate.

Independent 1/2/4 KiB host fixtures cover 444 immediate-persistence write/flush
cuts with cold recovery and old-or-new visible outcomes, plus creation, binding,
unsupported-profile and resource checks. All five host checks pass at
`/data/cache/partmgr-maintenance-ext-public-session-checks-20261011-v2/result.json`.
Renewed private fulljournal native evidence passed at
`/data/cache/partmgr-ext-owned-release-binding-20261011-v10/result.json`
(1,320 cuts, 121 distinct persisted images, 817 commands). The separate ordered
public append/create gate passed at
`/data/cache/partmgr-ext-ordered-release-binding-20261011-v2/result.json`
(2,448 cuts, 209 distinct preimages, 1,354 commands and nine same-owner
success snapshots). The entire ordered cut/recovery/read path uses the public
API. Independent descriptor
checks exclude regular-file data redo across all six ordered profiles; three
prior-fulljournal baselines reject at
`/data/cache/partmgr-ext-ordered-redo-negative-20261011-v2/result.json`.
The declared public ordered profile is qualified by the scoped host/native gates.
Further
ordered operations,
modern profiles, native mounted/hardware crashes and metadata/ACL editing remain
open under the maintenance plan.

The private classic namespace controller now seals mkdir, rename/move, file
unlink and empty-directory deletion with `NativeNamespacePatches`. Binding and
explicit namespace operation evidence are required; missing ordered evidence
cannot authorize arbitrary data operations. Every namespace patch is journaled,
including new directory bodies and indirect metadata. An independent bounded
scan of the original clean owner rejects redo destinations in any regular-file
payload block, including its invisible EOF tail.

The host namespace matrix covers 984 modeled interruption cases with cold
recovery at 1/2/4 KiB. All five required host/portable checks pass at
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

The strict NTFS audit excludes attribute lists and nonresident index bitmaps.
The explicit resolved audit includes bounded extensions, segmented allocations
and nonresident index bitmaps, while both profiles exclude compressed/encrypted
allocation and unsupported collations. An opened ADS or split MFT alone does
not establish complete ownership or write safety.
Selected user-tree capture excludes reserved objects and is not complete capture.
Security parsing and `$Secure` lookup do not establish Windows ACL restore/edit.
USN V2/V3 evidence decoding does not implement `$LogFile` recovery or USN lifecycle.

## Historical evidence ledger

These local files were reported present during the original inventory. The SHA-256 values below
identify the ledger documents themselves. Their complete artifact/source binding
graphs were **not reverified** for this change; historical pass results must not
be attached to changed sources without requalification. Local cache paths are
not portable published evidence URIs.

The 2026-10-11 owned-session follow-up could not find the historical ext
v11–v43 directories on this host. Their historical descriptions below remain
records of earlier runs, not current executable evidence. The fresh owned-session
qualification above is separate; the available foreign-recovery
receipts do not replace owned activation, publication and operation gates.

| Evidence document under `/data/cache/` | Historical scope | Document SHA-256 |
| --- | --- | --- |
| `partmgr-ext-jbd-codec-native-20261008-v43-draft/verification.json` | Private native ext positive operations; retained interruption subset | `ee1c2d1ef2c77682beb65e0149ea2cd46f5b334beb7ca5b7154cb0a5249a5b72` |
| `partmgr-ntfs-stream-native-20261008-v3/verification.json` | 21 DATA/ADS payloads, lists/extensions, ntfscat/TSK comparisons | `177c2dc10c4eb0ab8628b026bcd67e17665c1a5fb888961bae664904fae227aa` |
| `partmgr-ntfs-mft-split-native-20261008-v3/verification.json` | Split-MFT bootstrap read comparison | `18f5e6696dbef954f6156f51d998a2b0bb39bf561f9d9b43b76451a302373f46` |
| `partmgr-ntfs-object-root-native-v1/qualification.json` | 514 native security descriptors; ordinary-MFT fixture | `f215c70ab0acb3eb34c1c35e89882453ffd15a6df6f701bc55ae43978412a841` |
| `partmgr-ntfs-audit-native-20261008-final/receipt.txt` | Supported mkntfs ownership audit; not arbitrary Windows volumes | `8ac4a0bc1c6e18615b1d969cfaecc7af9c4db6c7eae1376077c5c44a089bd5fd` |

The ext v43 manifest reports pass, 43 source bindings, 32,537 artifact hashes,
304 modern deletion cuts, 912 legacy-256 deletion cuts and 72 additional legacy
positive operation models. Those counts do not establish every operation/profile
fault gate. Its scope explicitly leaves added legacy interruption matrices and
public admission outstanding. [The ext work log](filesystem-ext-journal-edit.md)
retains failed v19/v33/v34/v35/v37/v39 runs and failed verifier attempts. Failed,
partial and superseded evidence remains historical and never becomes acceptance
through a later successful run. [NTFS priorities](filesystem-ntfs-priority.md)
also distinguishes partial host logs, historical imports and native checkpoints.

## Required NTFS feature and research inventory

Every row requires independent inspect/decode/preserve/create/edit/repair/format/
grow/recovery status, profile prerequisites and immutable receipts. No row has
an unqualified complete status today.

| Required area | Existing foundation | Research/qualification needed |
| --- | --- | --- |
| Resident/nonresident unnamed DATA and ADS, including directories | Bounded exact stream enumeration/open and extension resolution | Whole-volume resolved ownership; Windows stream creation/range/append/truncate/rename/delete; resident transitions and native stream collation |
| Sparse/initialized allocation | Reader maps and bounded audits in accepted profiles | Zero exposure, allocation accounting, runlist updates, extension records and every restart cut |
| Names, hardlinks, SI/FILE_NAME timestamp views | Native provenance and selected namespace | `$UpCase`/`$I30` mutation, sequence reuse, all timestamp views, link/reference/index updates |
| `$LogFile` and reserved/system objects | Bounded 1.1 restart/physical-header inspection with scoped Windows evidence; no native writer | Extend version/geometry profiles; native multipage qualification, record succession, LSN ordering, transaction tables, redo/undo allowlists, checkpoint/wrap; Windows-authored foreign dirty fixtures and read-only replay overlay |
| USN absent/enabled | V2/V3 decoding and selected `$J` extraction | Authenticate `$J`/`$Max`, deletion states, retention and identity; native reason/close/rename/security/ADS records synchronized with `$LogFile`; absent stays absent by default |
| Security descriptors/ACLs | Lossless SID/ACE parser and bounded `$Secure` resolution | Windows owner/group/DACL/SACL comparisons and privilege checks; shared SDS placement/hash/index growth, exact null/absent/empty semantics and inheritance; no guessed reclamation |
| Native compression | Explicit bounded LZNT1 reads using published codec; no writable profile | Windows-authored full-unit/fragmented/ADS plaintext qualification; encoding and partial transactional writes, restart and crash replay |
| EFS | No complete plaintext write profile | Separate opaque preservation, raw backup/restore and authorized-key plaintext operations; native EFS metadata/recipient identity, Windows service fixtures, key failure zero-write and plaintext exposure accounting |
| EAs, reparse points, object IDs, quotas, change tracking | Partial native metadata inspection | Enumerate native indexes/system references and exact mutation semantics; pin fixtures for each supported operation |
| WOF/CompactOS, deduplication, TxF, filter reparse payloads | No admitted general mutation profile | Separate provider/profile decisions; opaque preservation cannot count as writable support |
| Format/grow/repair | Readers and profile audits only | Native system layout, boot/mirror/bitmap/log geometry, conservative redundancy repair and reviewed crosslink policies; Windows format/extend/chkdsk comparison |

EFS and BitLocker have independent key and durability contracts. Compression/EFS
combination rules require Windows fixtures; do not promise every stream-state
cross-product. Pin primary reference revisions and archived hashes from the
[specification ledger](filesystem-specifications.md) before accepting fixtures.
Unresolved wire fields require native experiments, not inferred encodings.

## Delivery tracking

| Stage | Status | Owner/scope and remaining exit |
| --- | --- | --- |
| P0 | Partial implementation | Maintenance API/inventory work; reviewed per-feature manifests, pinned references, numeric resource limits, complete corpus and dependency review still required |
| P1 | Foundations only | NTFS acquisition/read/security owners; resolved whole-volume ownership, complete capture and Windows VSS/ACL gates remain |
| P2 | Curated public classic-ext3 append/create/truncate/write_at/extend_sparse and hardlink/namespace API, with manifest-seven symlink lifecycle integrated and source-bound native/adversarial qualification plus final rehash passed for the archived snapshot; NTFS log foundation | Broader ext operations/profiles, complete native operation matrices and native NTFS recovery/write protocol remain |
| P3 | Pending | NTFS namespace/ADS/USN and ext metadata owners; actual mutation and both native USN states, ext ACL baseline and native fault gates remain |
| P4 | Pending | NTFS security/compression/EFS owners; valid combination matrix, Windows and recovery evidence remain |
| P5 | Partial implementation | Fresh empty classic ext2 formatting and same-final-group growth with scoped host/native gates; broader ext geometry, ext3/ext4 and NTFS format/grow/repair implementation and qualification remain |
| P6 | Pending | Per-family owners; native timestamp/metadata/ACL/journal and maintenance feature completion remains |

Owners here identify work areas, not assigned maintainers. Before accepting a
task, record a named owner, exact profile, prerequisite, implementation/portable/
native/fault/benchmark results, evidence URI/hash and exclusions. No stage is
complete because an API or this inventory exists. Executable baseline gates and
the missing qualification protocol are documented in
[integration/maintenance](../integration/maintenance/README.md).

## Current implementation checkpoint — 2026-10-13

The archived integrated host checkpoint passes all five checks against 428 host
inputs ([binding](/data/cache/partmgr-current-integrated-binding-20261013-v1.json)).
The private ACL session includes access/default changes, chmod and atomic child
creation with inherited ACLs, owned cold recovery, source guards and bounded
shared work. Native ACL writer qualification and public promotion remain open.
It includes the private classic-ext user-xattr lifecycle and host-compiled ignored
qualification harness, mounted-kernel ACL comparison fixtures, and NTFS
source-owned traversal, checkpoint/transaction/target analysis, dirty maps,
exact redo traversal, nonresident byte shadows and bitmap effects. Completed
physical reads survive cancellation and work refusal. The private modern
KEEP_SIZE planner/controller and actual session regressions are integrated;
native qualification and public modern write authority remain closed.
NTFS cached FILE deallocation, admitted shared undo effects and post-undo
MFT mirror shadows are integrated as read-only models. Original-byte acquisition
is provenance instrumentation; native cache/I/O outcomes, remaining operation
classes, xattr native qualification and durable NTFS publication remain open.
The records below retain each archived snapshot's scope rather than extending
its evidence to later changes.
Cached FILE initialization (opcode 2 redo/undo) has also been integrated as a
read-only model. The earlier five-check run covered a 428-input worktree,
including that snapshot's Cargo.toml/Cargo.lock
([binding](/data/cache/partmgr-current-integrated-binding-20261013-v1.json)).
Uncached initialization remains explicitly unsupported.

The repository implements the public `std` classic-ext3 ordered session at
manifest seven. Its symlink lifecycle passes host, source-bound native
interruption/recovery, adversarial verifier and final rehash gates for the
archived snapshot. All five
commands in the [host receipt](/data/cache/partmgr-maintenance-ext-symlink-checks-20261011-v5/result.json)
returned zero for the recorded 365-source snapshot. These results include the
required formatting, all-feature Clippy/tests and portable Clippy/tests.

The [native runner receipt](/data/cache/partmgr-ext-symlink-release-binding-20261011-v1/result.json)
records `complete: true`, with 50,208 cut rows, 3,833 unique preimages and
33 refusal cases. Its positive gate is accepted. The corrected
[25-control adversarial run](/data/cache/partmgr-ext-symlink-negative-controls-20261012-v2/result.json)
also records `complete: true`, binding 165,774 artifacts. The first run remains
failed because one mutation reached an unintended earlier assertion; the
corrected run preserves the required rejection cause. The
[independent adversarial rehash](/data/cache/partmgr-ext-symlink-negative-cached-independent-rehash-20261012-v2.json)
also passes all 25 exact causes and 165,774 exact artifact paths, including final
identity checks for every pathname. The
[combined final rehash](/data/cache/partmgr-ext-symlink-final-rehash-20261012-v2.json)
also records `complete: true`, binding 365 host sources, 225 compiled sources,
91,226 native artifacts and all 25 negative controls. Its receipt SHA-256 is
`8bcbdf79f9919847064c423408efb650ee4ed7e918b2792d8affed3477e6e9be`.
The native-authored input corpus below separately establishes fixture provenance.
Earlier accepted manifest-five and manifest-six results retain their archived
source scope. These offline results do not establish mounted or hardware crash
behavior, and do not qualify later staged implementation changes.

Modern extent-based KEEP_SIZE preallocation and its controller bridge, dedicated
allocation-counter repair, and an NTFS restart-context/endpoint seed have been
prepared outside the repository. The isolated combined draft passes all five
required host checks against 378 unchanged recorded sources
([host receipt](/data/cache/partmgr-combined-host-checks-20261012-v1/result.json)).
This includes compiled native-gate code, but those new writer gates have not
executed. These unintegrated changes confer no public capability in this checkout.
The later isolated owning counter-repair wrapper passes five consumer tests.
Its version-two preparation now durably retains the original primary superblock
and every primary group-descriptor block. Ten core repair/rejection tests and
three capsule tests pass, including already-checkpointed unmanaged-byte drift,
wrong operation scope, torn capsules and single/multiple descriptor blocks.
All five required checks pass for the updated
[384-source isolated snapshot](/data/cache/partmgr-combined-host-checks-20261012-v3/result.json),
with identical start/end manifests independently checked against the live draft.
Native interruption and adversarial qualification of this format remain open;
these results do not establish an integrated public repair API. In particular, there
is no implemented `CountRepairSession` or `PreallocateKeepSize` operation in the
current source. NTFS `$LogFile` inspection does not establish an authoritative
active window, replay overlay, recovery or transactional writing.
The isolated NTFS draft additionally compiles source-derived tail/fast-copy and
ordinary-page discovery. Three tail-transition, four ordinary-transition and
13 framed-byte API consumer tests pass. Lookahead now follows the native fixed
probe address, repeated-wrap generations and same-address reread; it retains
partial diagnostics on refusal and native 32-bit probe counts. The updated
[384-source host run](/data/cache/partmgr-combined-host-checks-20261012-v4/result.json)
passes all five required commands, with identical start/end/live source hashes. Tail overlay, authoritative active-page successors, native Windows
qualification, replay and writing remain open.

A subsequent NTFS implementation adds a source-owned immutable tail overlay and
record-derived successor observations. Its 16 framed-byte consumer tests and
three successor arithmetic tests pass in the
[focused host run](/data/cache/partmgr-ntfs-overlay-focused-checks-20261012-v2.json).
The tests verify native tail-bank provenance, normalized page reads and exact
same-source record assembly. Native inclusive-end alignment ambiguity remains
explicitly unsupported. Its nine source/test files are now integrated, matching
the isolated snapshot that passed all five host checks in
[the 388-source run](/data/cache/partmgr-combined-host-checks-20261012-v6/result.json).
All five repository checks pass in the
[374-source checkpoint run](/data/cache/partmgr-ntfs-checkpoint-analysis-host-checks-20261012-v1/result.json),
including partial-transfer correction, private physical traversal and exact
checkpoint selection. The
[integration binding](/data/cache/partmgr-ntfs-checkpoint-analysis-integrated-binding-20261012-v1.json)
verifies that every repository source matches the tested snapshot. Physical
traversal retains foreign/non-client dispositions, failed steps and repeated
restart/page guards; strict public exact-client queries remain intact. Checkpoint
selection handles direct restart lookup outside the traversal and starts the
analysis suffix after the selected anchor.

Read-only replay analysis is now integrated and matches the
[375-source full host run](/data/cache/partmgr-ntfs-replay-analysis-host-checks-20261012-v1/result.json)
and its [source binding](/data/cache/partmgr-ntfs-replay-analysis-integrated-binding-20261012-v1.json).
It loads checkpoint tables in native transactions/dirty/names/open order, retains
exact dump bodies and source guards, and projects transaction transitions over
the selected analysis suffix. The public strict record decoder remains unchanged.
Dirty/open/name effects, target ownership, redo/undo intents, complete active-window
authority and native Windows qualification remain unfinished; analysis does not
authorize recovery or writes. Residual partial-transfer counts authorize read-only mount refusal, not
page-erasure cleanup.

Preallocation, broader repair, metadata/ACL editing, modern public ext writing,
format/growth coverage and the remaining NTFS milestones still belong to the
unfinished maintenance plan. Host and offline persistence results do not
establish mounted concurrency, hardware crash durability, Windows servicing or
firmware boot correctness.

## Classic inode metadata input corpus — 2026-10-12

The isolated classic Linux inode128 metadata draft now has a native reference
corpus covering 90 cases across 1/2/4 KiB block sizes. Its 196 native commands
and 582 artifacts cover exact UID/GID, permission and raw access/modification/
change-time fields, including aliases, root, directories and unfollowed symlinks.
The [native receipt](/data/cache/partmgr-ext-inode-metadata-oracle-20261012-v1/receipt.json)
has SHA-256 `12e2acee035e273418a0977d97d137367348e26f081d9fbe5b1e0bc9255d74eb`;
the [independent rehash](/data/cache/partmgr-ext-inode-metadata-corpus-rehash-20261012-v1.json)
passes exact field counterfactuals and the complete artifact inventory.
This establishes reference fixture authorship only. The Rust implementation
remains isolated, with publication/recovery fault qualification pending. Flags,
xattrs, ACLs, inheritance and broader timestamp encodings remain E3 requirements.

The staged publication/recovery gate compiles and passes
[all five host checks](/data/cache/partmgr-metadata-native-host-checks-20261012-v2/result.json),
with 392 identical start/end/live source hashes independently verified. Its
251-file Rust/outer compiled-source inventory and embedded source paths are
checked separately. These host checks do not establish native fault qualification.

## ACL/xattr input corpus and isolated reader audit — 2026-10-12

The [native corpus](/data/cache/partmgr-ext-acl-xattr-oracle-20261012-v5/receipt.json)
contains six classic/modern profiles at 1/2/4 KiB, each with unique, shared,
replacement and removal stages. Its 816 commands and 1,940 artifacts pass an
[independent complete inventory and rehash](/data/cache/partmgr-ext-acl-xattr-corpus-rehash-20261012-v1.json).
The receipt SHA-256 is
`075d7eaa8460820e068f95fc6175009b5162f0a9b5ae71877c757b1d807f1446`.
Native ACL conversion canonicalizes ignored generic base-entry IDs to zero;
native shared removal retains an empty private xattr container and decrements
the surviving shared container's reference count. Failed acquisition attempts
remain preserved. This establishes fixture authorship, not mounted ACL semantics
or writer qualification.

The isolated codec and classic ownership-audit draft passes five focused
consumer tests and all five host checks with 376 unchanged sources. Its first
[native-input consumer run](/data/cache/partmgr-ext-acl-xattr-public-consumer-20261012-v1/result.json)
passed the 12 classic cases, then refused the first modern case because complete
audit lacked modern symlink support. The corrected isolated reader/audit adds
checksum-validated modern fast and single-block extent symlinks with external
xattr sector and ownership accounting. All five host checks pass for its
[376-source snapshot](/data/cache/partmgr-ext-classic-xattr-host-checks-20261012-v2/result.json).
The fresh [native consumer run](/data/cache/partmgr-ext-acl-xattr-public-consumer-20261012-v2/result.json)
passes all 24 cases, exact native names and symlink targets, opaque tree xattr
capture, source preservation and resource refunds. The combined implementation
is now integrated: all five host checks passed for the
[378-source snapshot](/data/cache/partmgr-ntfs-native-analysis-context-host-checks-20261012-v3/result.json),
and the [native reader rerun](/data/cache/partmgr-ext-acl-xattr-public-consumer-20261012-v3/result.json)
passed all 24 cases against that same snapshot. The
[integration binding](/data/cache/partmgr-ntfs-context-ext-xattr-integrated-binding-20261012-v1.json)
checks every current source hash. Its native NTFS context retains exact physical
reads consumed during volume opening and record-2 resolution, including boot and
MFT mapping evidence; seven regressions cover limits, transient consumed bytes,
source-owned geometry and callback cancellation. No active-window, recovery or
write authority is granted.

Private borrowed ACL mode reconciliation, chmod mask projection and creation
inheritance are now integrated. They preserve native named-entry order and
accepted duplicate IDs, distinguish mode-equivalent ACL removal, and avoid
applying umask twice when a default ACL exists. Four focused tests include
54 comparisons against exact primary-extracted Linux C algorithms; the
[algorithm review](/data/cache/partmgr-ext-acl-algorithm-oracle-review-20261012-v1.json)
separates those calculations from mounted effective-access evidence. All five
host checks pass for the [379-source snapshot](/data/cache/partmgr-ext-acl-semantics-host-checks-20261012-v1/result.json),
with exact current-source equality in its
[integration binding](/data/cache/partmgr-ext-acl-semantics-integrated-binding-20261012-v1.json).
A subsequent fresh no-default build exposed a missing test-only `alloc::vec::Vec`
import that the earlier cached check had not compiled. The explicit import is
fixed; [fresh no-default Clippy and all four ACL tests pass](/data/cache/partmgr-ext-acl-no-std-fresh-checks-20261012-v1.json).
Combined full validation is being repeated with refreshed source mtimes, and the
379-source binding describes the snapshot before this test import correction.
The subsequent combined [380-source gate](/data/cache/partmgr-ntfs-dirty-analysis-host-checks-20261012-v3/result.json)
passes all five checks, including the fresh no-default compilation. Source-owned
NTFS dirty-page analysis is integrated with exact source equality in its
[integration binding](/data/cache/partmgr-ntfs-dirty-analysis-integrated-binding-20261012-v1.json).
It preserves native slot/free-chain order, uses captured volume geometry for
duplicate normalization, and projects supported update/delete/hotfix effects
with finite slot/LCN work and retained source guards. Four new tests cover native
framed effects, source identity, allocation ceilings and mostly-free scan bounds.
Open/name effects, target intents, complete analysis and recovery remain open.
No public ACL mutation or effective-access engine is exposed. Atomic xattr
lifetime, stored ACL/mode coupling, mounted inheritance/access and recovery
qualification remain E3 requirements.

## Primary-counter repair input corpus — 2026-10-12

The independent [native corpus receipt](/data/cache/partmgr-ext-count-repair-oracle-20261012-v2/receipt.json)
contains 21 cases across three classic-ext3 profiles with 1/2/4 KiB blocks and
128-byte inodes. It records 145 native commands and 404 artifacts, independently
rehashed in the [corpus binding check](/data/cache/partmgr-ext-count-repair-corpus-rehash-20261012-v2.json).
Cases corrupt each of the five primary allocation counters separately, all five
together, and counters across all groups. Native repair restores the complete
image exactly to its clean baseline; regular payloads and hardlink aliases are
verified through native full-file dumps.

Read-only `e2fsck -f -n` can return zero while reporting a wrong counter and
refusing its repair. Every corrupted input therefore requires the exact native
diagnoses for its changed fields, an independent recount and byte-identical
source after inspection; exit zero alone does not establish cleanliness. The
first generator attempt remains failed and unaccepted. The accepted second
receipt has SHA-256
`1030e0a3c871eed606c5f047a8096352ddf2899dec822e98dc155ea615a0f132`.

This qualifies native-authored inputs only. The Rust counter-repair session and
its combined transaction-controller changes remain outside the repository,
host-tested in the isolated combined draft above, with native writer
qualification still open; no public repair capability is established.

The first native writer attempt was cancelled after an independent review found
that its outer runner and verifier omitted compiled test sources from their
required inventory. Its incomplete artifacts and
[cancellation receipt](/data/cache/partmgr-ext-count-repair-release-binding-20261012-v1/cancellation-20261012.json)
are retained; they do not qualify the writer. The corrected isolated draft
passes [all five host checks](/data/cache/partmgr-count-repair-corrected-host-checks-20261012-v1/result.json)
with 384 unchanged sources and an exact 243-file compiled-source inventory.
Its fresh optimized build is undergoing native qualification; acceptance remains
pending until the writer, independent verifier and adversarial controls finish.

## Manifest-seven symlink input corpus

Native-authored classic-ext3 symlink inputs are retained at
`/data/cache/partmgr-ext-symlink-oracle-20261011-v1/receipt.json`
(SHA-256 `661553227d2108ed7d10adc22213f76053d314f1c3754bb70d6297275fe66ee5`).
The completed corpus contains nine models, 180 prospective operation cases,
nine unusual-target models, 558 successful native commands and 1,298 independently
rehashed artifacts. It includes fast/slow boundary targets, aliases, single-link
final-unlink baselines, packed parents and genuine native-filled no-free images.
No-free prerequisites include independent block/inode bitmap and free-counter
recounts and directory insertion-slack checks. Unusual targets cover dangling,
dot components, absolute paths, self references and cycles as raw bytes.

This is input-fixture evidence only. Symlink writer, audit, public API and native
gate/verifier are integrated in the repository and all five source-bound host
checks, source-bound native interruption/recovery, adversarial controls and final rehash pass for the archived snapshot. Native non-UTF8, whitespace, quote and backslash target
coverage remains open. The existing reader's support does not imply write support.

## Modern preallocation input corpus — 2026-10-12

The [accepted native input corpus](/data/cache/partmgr-ext-modern-preallocation-oracle-20261012-v7/receipt.json)
contains 90 cases across six 1/2/4 KiB profiles with metadata checksums or
group-descriptor checksums, including uninitialized groups. All 5,871 native
commands succeeded; 12,862 artifacts were independently bound in the
[corpus rehash](/data/cache/partmgr-ext-modern-preallocation-corpus-rehash-20261012-v7.json).
The cases include 72 allocating operations, 12 no-ops and six storage-full
refusals, native extent-tree depth transitions and preserved initialized and
unwritten backing bytes. Failed earlier corpus attempts remain unaccepted.

This receipt qualifies the inputs. The isolated Rust KEEP_SIZE implementation
has host coverage but still requires execution of its source-bound native
interruption/recovery gate before any public modern-writer claim.


## Pending qualification updates — 2026-10-12

The disposable Linux ACL guest completed 34 cases and 22 exact native ACL
comparisons. Its artifacts were copied back and independently rehashed in
[the copyback receipt](/data/cache/partmgr-acl-kernel-20261012-v1/copyback-v1.json).
Only our `partmgr-acl-kernel-20261012-v1` VM was stopped; its launcher exited
successfully and all base-file hashes remained unchanged, as recorded in
[the shutdown verification](/data/cache/partmgr-acl-kernel-20261012-v1/shutdown-base-verification-v1.json).
Comparison against the current Rust implementation remains required; these
results alone do not qualify a public ACL writer.

The isolated xattr lifecycle draft v4 failed host compilation. Its
[failed host receipt](/data/cache/partmgr-ext-xattr-cow-host-checks-20261012-v1/result.json)
is retained; this draft has not been integrated or qualified.

The count-repair Rust interruption matrix finished successfully, but independent
native verification failed. Investigation found that replay's `e2fsck -f`
overrode `journal_only` and ran full repairs on deliberately inconsistent OLD
counters. A separate verifier correction is under review; the exact OLD/NEW
comparison and remaining adversarial controls have not passed. Count repair
therefore remains unqualified and isolated.


## NTFS open/name analysis host integration — 2026-10-12

Private native open-attribute/name analysis is integrated after all five host
checks passed against 381 unchanged source files. The
[integration binding](/data/cache/partmgr-ntfs-open-analysis-integrated-binding-20261012-v1.json)
records the complete source closure. Coverage includes initial names in source
order, duplicate replacement, declared-slot versus full-source bounds, native
open-slot extension, retained-name peak memory and dirty updates after open
records. A failed earlier fixture used an unaligned physical record end; its
receipt remains retained and the corrected framed fixture passed.

This layer grants no recovery or filesystem mutation authority. Native target
resolution, provisional intents, attribute winner/run reconstruction and actual
redo/undo filesystem effects remain required for N2. The corrected count verifier's fresh run subsequently rejected a recovery-flag-clear
image with pending journal data: native e2fsck prompted for replay and then ran
full repairs despite journal_only. This failed attempt is preserved in
[the postprocess receipt](/data/cache/partmgr-ext-count-repair-postprocess-20261012-v2/result.json).
A native replay-only mechanism remains required; exact OLD/NEW checks stay
unchanged and count repair remains unqualified.


## Mounted ACL projection comparison — 2026-10-12

The isolated current-Rust comparison passed all 18 captured ext3/ext4
inheritance/chmod cases, covering file/directory creation under umasks 000, 027
and 777. The [focused execution log](/data/cache/partmgr-acl-rust-guest-comparison-host-checks-20261012-v2/check-0.log)
records the actual test execution. An independent decoder checked the embedded
native-v1 literals against the captured generic-v2 observations; the
[external input binding](/data/cache/partmgr-acl-rust-guest-comparison-external-binding-20261012-v2.json)
records the receipt, 22 native ACL artifacts and comparison source. The focused comparison and all five host checks subsequently passed against
381 unchanged source files. External inputs were rehashed, the executed focused
test binary was archived, and the comparison test was integrated with an
[exact source binding](/data/cache/partmgr-acl-rust-guest-comparison-integrated-binding-20261012-v1.json).

The guest's real credential access probes remain separate kernel evidence;
this comparison does not implement or qualify a Rust effective-access evaluator,
a public ACL writer, or durable inheritance during namespace mutation.


## Xattr lifecycle verification update — 2026-10-12

The isolated v6 draft passed formatting and all-feature Clippy, then failed its
actual shared-COW/remove/cold-recovery unit test: cold recovery rejected original
home ordering/content. The [failed test log](/data/cache/partmgr-ext-xattr-cow-host-checks-20261012-v3/check-2.log)
records 299 passed, one failed and 41 ignored unit tests. This is an implementation
failure; the draft remains isolated. The subsequent isolated v7 canonical-ordering fix passed both the previously
failing lifecycle test and the new full native preparation/parser round-trip
regression in its [active host log](/data/cache/partmgr-ext-xattr-cow-host-checks-20261012-v4/check-2.log).
The complete all-feature suite subsequently passed, but no-default-features
Clippy failed because private planner/session modules referenced the std-gated
journal module. The [failed gate receipt](/data/cache/partmgr-ext-xattr-cow-host-checks-20261012-v4/result.json)
is retained; feature-gating correction and independent native interruption
qualification remain pending. The implementation is still isolated.

A separate [native writer input corpus](/data/cache/partmgr-ext-xattr-writer-oracle-20261012-v3/receipt.json)
completed 21 classic user-xattr cases across 1/2/4 KiB blocks, with 147 successful
commands and 468 artifacts. The [independent rehash](/data/cache/partmgr-ext-xattr-writer-corpus-rehash-20261012-v3.json)
verified the exact artifact inventory, baseline inputs and tools. Cases include
shared replacement/removal/creation, private removal, empty-private creation,
identical-value set and absent-key removal. Native allocation choices are
independent goldens for value/ownership semantics; this corpus alone does not
qualify the Rust writer or establish exact Rust/native physical layout equality.


## Native replay primitive validation — 2026-10-12

A separately built helper using pinned native JBD replay code passed initial
inactive-OLD, active-OLD and active-NEW exact filesystem-byte probes without the
accounting timestamp changes introduced by e2fsck/debugfs frontends. This is
primitive-level journal replay with explicit owned recovery-fence completion,
not proof of full e2fsck recovery equivalence.

A subsequent injected native I/O failure showed that upstream replay can log a
write error while returning success. The [failed probe artifacts](/data/cache/partmgr-count-native-jbd-primitive-probe-20261012-v5)
remain preserved. The helper is not accepted: callback error tracking and
failure-before-fence-clear controls are required, together with pinned file
identity, complete source/tool bindings and independent review. Count repair and
xattr native interruption qualification remain pending; successful native return
codes alone cannot close them.


## NTFS source-owned target intents — 2026-10-12

Private target observations and provisional intents are integrated after all
five host checks passed against 383 unchanged source files. The
[integration binding](/data/cache/partmgr-ntfs-target-intents-integrated-binding-20261012-v1.json)
records the complete source closure and test-only field/format corrections.
Four framed consumer tests cover source-derived existing attribute candidates,
missing-attribute provisional descriptors, finite capture/work refusal and
repeated consumed physical reads.

Unused slots, sequence conflicts and targets outside the logical MFT remain
explicit unsupported observations: generic reader rejection does not establish
native cold-replay or cached-inode lookup behavior. No owner or provisional
attribute is fabricated for those outcomes. Native attribute winner selection,
source-owned UpCase/list ordering, run-cache reconstruction, dirty run merging,
actual redo/undo effects and durable publication remain required for N2. These
host checks grant no recovery authority or native Windows qualification.


## Private xattr lifecycle host integration — 2026-10-12

The subsequent v8 feature-gating correction, combined with integrated NTFS
target observations, passed all five host checks against 388 unchanged source
files. The private classic user-xattr lifecycle is now integrated with an
[exact source binding](/data/cache/partmgr-ext-xattr-cow-integrated-binding-20261012-v1.json).
Earlier isolated/failing v4–v7 attempts remain historical evidence.

The implementation covers deterministic external EA encoding, source-bound
ownership planning, shared-block COW/refcounts, native empty-private-container
removal, intent-bound owning sessions and separately scoped preparation/cold
recovery. Canonical home ordering and full preparation/parser round-trip tests
pass. Planner, recovery and session modules follow the std journal boundary;
the deterministic encoder remains available to portable builds.

This host integration grants no public xattr writer admission. Independent
native golden comparison, complete operation/recovery persistence and torn-write
matrices, source/capsule/callback controls and final source-bound native receipts
remain required. Modern checksum/lifetime profiles, ACL/security key edits and
the remaining E3 operations are still unfinished.
The current 21-case native corpus starts with existing external EA containers.
Supplementary first-allocation fixtures now cover 1/2/4 KiB blocks
([native inputs](/data/cache/partmgr-ext-first-external-ea-oracle-20261012-v1/receipt.json)).
Independent [file rehash](/data/cache/partmgr-ext-first-external-ea-root-rehash-20261012-v1.json)
and [direct byte checks](/data/cache/partmgr-ext-first-external-ea-root-byte-review-20261012-v1.json)
confirm their provenance and scoped inode/EA/accounting transitions. Inclusion
in the Rust interruption/recovery matrix and native qualification remain open.

## NTFS attribute winner and physical run integration — 2026-10-12

The isolated winner/run draft passed all five host checks against 390 unchanged
source files ([results](/data/cache/partmgr-ntfs-target-winner-host-checks-20261012-v3/result.json),
[source inventory](/data/cache/partmgr-ntfs-target-winner-host-checks-20261012-v3/sources-end.json)).
Independent native-source review found no blocker within the admitted scope.
The six implementation/test files and compiled inventory are now integrated;
all 390 repository source hashes match the passing snapshot
([integration binding](/data/cache/partmgr-ntfs-target-winner-integrated-binding-20261012-v1.json)).

The draft follows pinned native attribute/list order and source-owned UpCase
comparison, then decodes physical mapping pairs and applies source-ordered run
replacement without clipping to file EOF. Four modeled run tests and two framed
consumer fixtures exercise overlap, sparse delta history, finite resources,
private ADS runs and attribute-list early termination. These checks cover
admitted ordinary regular-file contexts. Directory index admission, special
inode modes, cold/cached lookup ambiguities, dirty run merging, redo/undo and
durable publication remain unfinished; this integration grants no recovery authority.

## Native JBD replay primitive review — 2026-10-12

The v4 private verifier helper closes the earlier profile and swallowed-I/O-error
findings. It pins the owned regular image, requires exact classic journal
features and 1/2/4 KiB geometry, records native read/write/flush failures, and
checks them before completing the explicit owned RECOVER fence. Thirty profile
probes, six reachable fault cases, strict OLD/NEW probes and nine payload checks
passed. Root rehashed all 2,717 bound files; independent review also closed
([peer closure](/data/cache/partmgr-native-jbd-primitive-peer-closure-20261012-v4.json)).

This helper runs native journal replay plus explicit owned fence completion;
it does not establish full e2fsck accounting equivalence. Failed durability after
fence clearing remains uncertain. Count-repair interruption qualification and
active xattr WAL qualification still require their complete source-bound gates.

The first postprocessing attempt using this helper stopped before issuing native
commands because strict regular-file capture rejected the upstream
`RELEASE-NOTES` source symlink
([failed attempt](/data/cache/partmgr-ext-count-repair-postprocess-20261012-v3/result.json)).
The independently reviewed verifier revision binds that single link's original
text and identity, its already-hashed canonical regular target, and final link
state. Executable capture remains sealed and requires a regular file. The fresh
attempt has not yet established qualification; earlier failures remain retained.

## NTFS source-ordered dirty maps — 2026-10-12

The reviewed v4 dirty-map implementation is integrated after all five host
checks passed against 391 unchanged source files
([binding](/data/cache/partmgr-ntfs-target-dirty-runs-integrated-binding-20261012-v1.json)).
It preserves original source mappings, applies dirty-table single-cluster
replacements in source order, shares existing unnamed DATA maps across open
slots while keeping copied attribute sizes separate, and derives the native
redo-start candidate from the filtered analysis seed and table minima.

The same-LCN regression ensures an unchanged mapping bypasses splitting and
does not falsely exhaust a one-run ceiling. Framed tests also cover provisional
private maps, immutable original evidence, shared maps, finite resource refusal
and refunds. Directory/special-mode admission, cold/cached ambiguities, exact
redo traversal and effects, undo and durable publication remain required. Both
active-window and recovery authority remain false.

## Private xattr qualification harness host integration — 2026-10-12

The reviewed v9 harness is integrated after all five host checks passed against
393 unchanged source files
([binding](/data/cache/partmgr-ext-xattr-native-harness-integrated-binding-20261012-v1.json)).
Its ignored tests cover independent immediate-write/failed-flush persistence
policies, operation and nested recovery cuts, explicit duplicate-parent joins,
active OLD/NEW source controls, both actual callback phases, resealed preparation
controls and finite resource preflight. Cut inventories are checked and charged
before allocation; artifact, work, row and inventory caps are explicit.

Host checks compile these ignored tests; they do not execute native qualification.
Compiled-source capture wiring, the independent verifier and outer runner,
whole-process limits, bound planning and complete native execution remain open.
First-time external EA allocation is also outside the current 21-case corpus.

## Xattr source capture and verifier candidate — 2026-10-12

The isolated source-capture and verifier candidate passed all five host checks
against 417 unchanged host inputs, including examples and benches
([results](/data/cache/partmgr-ext-xattr-qualification-host-checks-20261012-v2/result.json)).
Its native libtest source inventory contains 396 inputs. These inventories have
different scopes; neither result establishes native interruption qualification.
The candidate remains outside the integrated implementation while the combined
24-case native corpus, bounded outer runner and complete native execution are
prepared. The existing 21-case corpus remains preserved unchanged.

## Combined xattr native input catalog — 2026-10-12

The combined catalog preserves the original 21 cases and three first-external-EA
allocation cases under separate namespaces. Root independently rehashed all
578 catalog artifacts and confirmed 24 models
([identity review](/data/cache/partmgr-ext-xattr-combined-root-rehash-20261012-v1.json)).
This catalog derives from the retained native runs; it performs no new native
execution and does not qualify the Rust writer. The corresponding complete
24-case Rust interruption gate remains pending.

## Exact NTFS redo traversal and byte shadows — 2026-10-12

The independently reviewed v2 candidate is integrated after all five host checks
passed against 415 unchanged host inputs
([binding](/data/cache/partmgr-ntfs-redo-exact-integrated-binding-20261012-v2.json)).
It starts the native query at the source-derived redo LSN, preserves native skip
and allocation-width decisions, and models admitted nonresident byte updates as
readonly physical shadow fragments in execution order. Exact consumed source
reads are captured and rechecked with finite work and memory limits.

Actual framed consumer tests cover source-derived entry, byte effects, retained
original evidence and resource refusal. Raw capture regressions cover late
cancellation, length drift and exact work ceilings. Writes overlapping captured
log-query bytes require an ordered shadow-log reader and remain unsupported.
FILE/index/bitmap/mapping effects, full undo and durable publication remain open;
active-window and recovery authority remain false.

## Qualification review findings — 2026-10-12

Eleven focused adversaries passed for the candidate xattr outer runner's input
capture, sealed execution and original-descriptor log consumption
([root review](/data/cache/partmgr-ext-xattr-outer-mechanisms-root-review-20261012-v1.json)).
This does not qualify the writer or the full runner. Independent review found
that nested recovery retries retain final images but omit their actual write
attempt traces. Those traces must be archived and checked against destination
and byte-change constraints before native qualification can establish the
required write scope. Corrected source, verifier and resource planning remain
pending; the earlier candidates are preserved without qualification.

## Native tool identity correction pending — 2026-10-12

Independent review found that the current count postprocessor seals its replay
helper but invokes e2fsck/debugfs through live pathnames. The running attempt
continues to provide diagnostics; it cannot establish the required executed-tool
identity. A separately versioned correction will execute captured, hash-bound
native tool bytes and preserve the original frozen Rust evidence. No Rust matrix
rerun is needed for that postprocessing correction. The metadata verifier has a
corresponding unexecuted correction candidate; neither correction is qualified.

## NTFS runtime bitmap and retained reads — 2026-10-12

The reviewed v3 runtime changes are integrated after all five checks passed
against 415 unchanged host inputs
([binding](/data/cache/partmgr-ntfs-native-runtime-integrated-binding-20261012-v3.json)).
They retain bounded target-header/map copies, model native bitmap set/clear
masks, preserve native dirty-volume observations and continue the suffix where
required. Completed physical reads are retained before post-read cancellation,
length checks or charged shadow overlays can fail. Actual framed regressions
cover bitmap bytes, post-read cancellation and exact-work refusal with retained
read evidence. Source observations remain readonly; complete FILE/index effects,
undo, durable publication and recovery authority remain open.

## Corrected 24-case xattr host checkpoint — 2026-10-12

The isolated 24-case qualification snapshot, including nested retry traces,
passed all five host checks against 418 unchanged inputs
([results](/data/cache/partmgr-ext-xattr-qualification-24-host-checks-20261012-v3/result.json)).
The frozen producer matches those tested bytes. Native libtest capture covers
397 inputs; examples and benches are included in the larger host inventory.
The optimized build passed using the separate native-qualification Cargo profile
under the existing shared target directory and verified preservation of the
frozen count-repair release binary
([build receipt](/data/cache/partmgr-ext-xattr-custom-profile-build-20261012-v1/receipt.json)).
Bounded resource planning is running; the native matrix, adversarial controls and
final qualification remain pending. Host and build results do not establish
native writer qualification.

## Sealed-tool count postprocessing attempt — 2026-10-12

The reviewed v6 postprocessor is running in a fresh evidence directory with
captured, sealed e2fsck/debugfs/helper execution. Root independently verified all
three script hashes and the durable peer review before launch
([preflight](/data/cache/partmgr-count-postprocess-v6-root-preflight-20261012-v1.json)).
It reuses the original frozen Rust matrix and keeps the earlier diagnostic
attempt separate. Complete positive replay, nine fatal binding controls, 35
adversarial controls and final rehash remain required; no count-repair native
qualification is established by starting this attempt.

## Rebased metadata host checkpoint — 2026-10-12

The metadata candidate passes all five host checks against 421 unchanged host
inputs ([results](/data/cache/partmgr-metadata-current-qualification-host-checks-20261012-v1/result.json)).
All 421 match the frozen producer; its 422nd input is rust-toolchain.toml,
separately bound by the optimized build driver. Independent merge review closed
without a concrete blocker, including preservation of current ACL/xattr/NTFS
sources and the distinct metadata authority at both publication guard phases.
The candidate remains outside the integrated repository. Its source-bound
optimized build passed while preserving both earlier frozen gate binaries
([build receipt](/data/cache/partmgr-metadata-custom-profile-build-20261012-v1/receipt.json)).
The first outer-runner attempt stopped before Rust or native execution because
its fixed source inventory appended a stale count-repair test filename. That
failed attempt is preserved at
[/data/cache/partmgr-metadata-native-qualification-20261012-v1](/data/cache/partmgr-metadata-native-qualification-20261012-v1).
The corrected v2 outer runner matches the exact 257 compiled inputs and passed
eight focused controls plus independent review. It also retains the narrowly
bound native source RELEASE-NOTES symlink during final integrity checks
([review](/tmp/partmgr-metadata-current-outer-draft-v2/independent-outer-review.json)).
The fresh attempt is running at
[/data/cache/partmgr-metadata-native-qualification-20261012-v2](/data/cache/partmgr-metadata-native-qualification-20261012-v2).
All 90 native cases, fatal bindings, 42 adversarial controls and final rehash
remain required; host and build checks confer no native writer qualification.

## NTFS FILE deallocation draft regression — 2026-10-12

The unintegrated FILE v4 draft's focused framed regression compiled, then failed
with `NTFS resident dirty target native union semantics`
([failure binding](/data/cache/partmgr-ntfs-native-file-runtime-focused-check-20261012-v4/failure-binding.json)).
The revised fixture passes the earlier missing STANDARD_INFORMATION point;
this does not establish correctness of deallocation. The failed run and unchanged
source inventory are preserved. Dirty-target semantics, source-owned undo
traversal and subsequent mirror finalization remain required before integration.
The subsequent fixture-only v5 restores the existing native OpenAttr name length,
selecting genuinely absent named DATA instead of projecting a nonresident union
onto resident DATA. The production refusal remains intact. Its focused regression
passes against 416 unchanged inputs
([result](/data/cache/partmgr-ntfs-native-file-runtime-focused-check-20261012-v5/focused-result.json));
this result does not replace the remaining runtime work or all five host checks.

## Interrupted qualification attempts and fresh runs — 2026-10-12

The earlier count postprocessing v5, xattr resource planning v1, metadata gate
v2 and modern host-check v1 processes are no longer present. Their incomplete
receipts are preserved
([observation](/data/cache/partmgr-qualification-interruption-observation-20261012-v1.json)).
Count postprocessing v6 is running in a fresh output directory and reuses the
original completed Rust matrix. Metadata gate v3 and xattr resource planning v2
are fresh attempts: their interrupted matrices/planning totals were incomplete
and cannot establish qualification. No exhaustive xattr shards have launched.

The current modern KEEP_SIZE candidate preserves unrelated current sources,
but fresh host checks stopped at Clippy because its private session operation
has no construction site. Session-path tests remain required; the candidate is
not integrated. The separate ACL v4 candidate, including COW planning and cold
capsule derivation, passed formatting but failed compilation because its test
harness omitted the Storage trait import. The fresh v5 compile snapshot adds
that import but exposed inherited codec-test signature mismatches and a borrowed
plan drop error. Those failed outputs remain preserved. Producer v7 fixes the
test issues and adds a distinct ACL durable controller and cold session. The
subsequent v8 fixes a remaining borrowed-owner drop in the codec test; its
isolated compile snapshot is prepared for host checks. Root static review covers
both actual publication guards and cold source revalidation
([review](/data/cache/partmgr-ext-acl-v8-root-static-review-20261012-v1.json)). Atomic namespace
inheritance and native qualification remain incomplete.

The modern candidate now includes actual Session::operate KEEP_SIZE regressions.
All five host checks pass against 417 unchanged inputs in the fresh v3 attempt
([results](/data/cache/partmgr-modern-current-host-checks-20261012-v3/result.json)).
All three new actual session regressions pass: publication and
unwritten ownership/no-op handling, post-preparation source drift, and foreign
owner refusal. This does not establish native or public writer qualification.
The fresh ACL v9 compile snapshot is running host checks and additionally tests
unmanaged-block preservation plus a write-free second cold recovery at each
modeled write/flush failure boundary. Volatile/torn writes, interrupted recovery
and native verification remain separate required gates.
The subsequent v10 fixes a Clippy-only non-Drop observation lifetime issue and
passes formatting plus all-feature Clippy. Its new capsule and controller tests
fail because the configured proof/bootstrap ceilings exclude the fixture's
journal geometry
([focused diagnostics](/data/cache/partmgr-ext-acl-v10-focused-failure-diagnostics-20261012-v1/result.json)).
The fixture and explicit limits must be reconciled before these tests can support
controller correctness; no ACL lifecycle acceptance follows from compilation.
The v10 suite terminated with 325 passed, two failed and 45 ignored. A fresh v11
snapshot changes only the test journal ceiling from 256 to the fixture's actual
1,024 blocks, preserving production limits and the existing finite work envelope
([bound review](/data/cache/partmgr-ext-acl-v11-fixture-bound-review-20261012-v1.json)).
Its capsule test passes. The suite terminated with 326 passed, one failed and
45 ignored: the controller restart test fails at cut 48, where the recovered
primary has NEW free-block accounting while the test expects OLD
([diagnostics](/data/cache/partmgr-ext-acl-v11-focused-controller-failure-20261012-v1/result.json)).
The clean-restart Noop outcome and whole-home OLD/NEW oracle are being checked;
controller acceptance remains open.

The separate NTFS mirror/undo v7 candidate is undergoing host checks after a
narrow rebase preserving the FILE v5 fixture. It adds shared FILE/nonresident/
bitmap undo effects, explicit action-error traversal behavior and post-read
cancellation observations. Other FILE/index operations and post-undo mirror
finalization remain incomplete; this candidate grants no recovery authority.
The v8 compile snapshot fixes two style-only Clippy findings and passes
formatting/all-feature Clippy; its test suite is running. Independent review
identified a possible cached FILE undo overlap with later consumed log-query
bytes. That guard/proof must close before integration, regardless of host results.

The atomic ACL birth candidate creates the child and derives inherited ACLs,
allocation, namespace and counters in one typed plan. Its fresh v11 compile
snapshot preserves all five integrated modern KEEP_SIZE files
([rebase](/data/cache/partmgr-ext-acl-birth-modern-rebase-20261012-v11.json)).
The corrected restart oracle requires one coherent complete OLD or NEW home set
when an already-clean cold recovery returns Noop. Combined host checks are queued;
atomic birth and its native qualification are not yet accepted.
The NTFS v8 discovery-consumer suite terminated with 65 passed and three new
undo tests failing with shared resource-budget exhaustion
([host results](/data/cache/partmgr-ntfs-native-mirror-undo-host-checks-20261012-v8/result.json)).
Both resource accounting/fixture bounds and the cached FILE overlap finding
remain under investigation; the candidate is not integrated. Combined ACL birth
v11 host checks are now running against the modern-preserving snapshot.

The combined ACL birth v11 attempt passed formatting but failed compilation on
two nested-module paths in the new birth module. A fresh v12 snapshot corrects
those paths and rejects names exceeding the on-disk 255-byte limit before
allocation. Its five host checks are running
([results](/data/cache/partmgr-ext-acl-birth-host-checks-20261012-v12/result.json));
no ACL integration or native qualification is claimed. The count postprocessor,
metadata native matrix and xattr resource planner were each confirmed live by
polling their existing process handles; no replacement jobs were launched.

Combined ACL birth v12 terminated with formatting/all-feature Clippy passing
and 334 library tests passed, one failed, 45 ignored. The failure is the new
inherited-directory case: equal division of the aggregate encoding work budget
leaves the second pass unable to cover its intermediate-source and output
validations. The correction will share the unchanged aggregate ceiling across
both passes, with exact-boundary tests; this candidate remains unintegrated.

A fresh NTFS mirror/undo v9 snapshot preserves the integrated modern files and
applies a derived six-read fixture capture limit plus charged overlap checks
for every cached FILE write against all consumed redo/undo queries. Its five
host checks are running
([results](/data/cache/partmgr-ntfs-native-mirror-undo-host-checks-20261012-v9/result.json)).
Independent re-review and successful combined checks are required before
integration.

Independent re-review closes the cached FILE overlap finding for NTFS v9:
each cold/read or cached/write segment checks all retained redo and undo query
ranges before appending an effect
([review](/tmp/partmgr-ntfs-cached-file-correction-acl-agent-review-20261012-v1.json)).
Root verified all four reviewed file hashes against the test snapshot. Formatting
and all-feature Clippy pass; all-feature tests remain live.

ACL birth v13 is prepared with shared aggregate encoding work, preserving the
existing one-million work ceiling and adding exact-budget/one-below tests
([preparation](/data/cache/partmgr-ext-acl-birth-v13-root-preparation-20261012-v1.json)).
Its host checks await the current NTFS build. Native ACL authoring v4 passes
static checks for 57 models and five malformed-EA refusals; native execution and
complete crash/recovery trace qualification remain open.

NTFS mirror/undo v9 passes formatting and all-feature Clippy, but the
all-feature suite terminates at discovery-consumer tests: 67 passed, one failed.
The three prior memory-budget failures are resolved. The remaining header-growth
assertion expects 51,712 bytes while the observed value is 262,144; native
growth semantics and the existing fixture allocation must be reconciled
([results](/data/cache/partmgr-ntfs-native-mirror-undo-host-checks-20261012-v9/result.json)).
No integration follows from this failed run. ACL birth v13 host checks have now
started against the prepared aggregate-budget correction
([results](/data/cache/partmgr-ext-acl-birth-host-checks-20261012-v13/result.json)).

ACL birth v13 stopped on a test-only Clippy non-Drop finding. Fresh v14 removes
only that unnecessary drop. Formatting and all-feature Clippy pass. The running
all-feature suite now passes the exact aggregate-budget/one-below regression,
atomic child creation with inherited ACLs, and the controller's every-write/flush
restart test
([host evidence](/data/cache/partmgr-ext-acl-birth-host-checks-20261012-v14/check-2.log)).
Full host acceptance and native qualification remain open.

The NTFS header test has a source-derived correction: VCN 600 requests growth
beyond the fixture's existing 262,144 bytes, rather than expecting VCN 100 to
shrink native allocation. It is combined with the new bounded post-undo mirror
shadow finalizer in a prepared v10 snapshot
([preparation](/data/cache/partmgr-ntfs-mirror-finalizer-v10-root-preparation-20261012-v1.json)).
Its independent review and host execution are pending.

ACL birth v14 completes all five host checks successfully with 425 unchanged
captured inputs
([results](/data/cache/partmgr-ext-acl-birth-host-checks-20261012-v14/result.json)).
This is host evidence for the private candidate; native crash qualification
and integration remain separate. The modern native v3 candidate's host checks
have started. Its separate helper v6 build failed because the compiler include
paths omit the existing jfs_user.h directory; the failed attempt is retained
([diagnostics](/data/cache/partmgr-modern-native-jbd-helper-build-20261012-v1/build.stderr)).

The NTFS mirror finalizer correction classifies raw original-byte acquisition
as provenance work rather than an observed native cache-miss I/O outcome.
Independent v3 re-review closes the original cache/read classification finding;
v4 additionally withholds source_after until all overlays complete. A fresh
v11 compile snapshot is prepared for host checks; full native cache and I/O
outcomes remain unmodeled.

Independent full ACL lifecycle review is still open after the passing host run:
the reviewer is checking whether nested codec/controller work consumes the
parent aggregate ceiling or can reuse it. Passing host tests do not settle that
resource-accounting invariant, and the 10-file candidate is not integrated.

Root rehashed the corrected NTFS mirror v4 peer receipt and every reviewed
source, then matched the prepared v11 snapshot
([binding](/data/cache/partmgr-ntfs-finalizer-v11-root-peer-binding-20261013-v1.json)).
No source blocker remains in that review; host checks are queued. Source/cache
acquisition remains explicit provenance instrumentation, with no native cache
I/O or durable recovery qualification claimed.

The modern helper's second build attempt fails at missing blkid/blkid.h
([diagnostics](/data/cache/partmgr-modern-native-jbd-helper-build-20261012-v2/build.stderr)).
The complete accepted include configuration is being derived before another
fresh attempt. The modern candidate passes formatting and all-feature Clippy;
its full tests and the original count, metadata and xattr-planning process
handles remain live.

The ACL aggregate-work concern is confirmed for birth: unlike the ordinary
planner, it does not charge the nested five-times encoding allowance to shared
Work.used. Independent review records this as an integration blocker
([review](/tmp/partmgr-ext-acl-birth-v14-peer-review-20261013-v1.json)).
A fresh production correction and resource-boundary regression are being
prepared; the passing v14 snapshot remains immutable and unintegrated.

The superseding ACL v14 review identifies a second aggregate-cost gap: the
prepared-phase source guard adds a source-block × journal-membership scan that
the lifecycle's linear envelope does not separately reserve
([review](/tmp/partmgr-ext-acl-birth-v14-peer-review-20261013-v2.json)).
Both birth nested-work charging and this additional controller cost must be
corrected and checked before integration. No additional ownership or durability
ordering defect was identified by that source review.

The modern native v3 candidate completes all five host checks with 421
unchanged source inputs
([results](/data/cache/partmgr-modern-native-current-host-checks-20261012-v3/result.json)).
The native helper and exhaustive native matrix are not yet qualified. Corrected
NTFS finalizer v11 host checks have started. ACL birth v15 is prepared with
checked nested-work charging and a separate prepared-phase source/journal
membership allowance; both configured ceilings remain unchanged. Its independent
review and host checks are pending.

The corrected modern helper v9 builds both normal and fault binaries
successfully with -Werror retained. Root rehashed accepted sources, crypto/util
libraries, local inputs and all 213 compiler dependencies after the build
([build receipt](/data/cache/partmgr-modern-native-jbd-helper-build-20261012-v4/receipt.json)).
Standalone profile/refusal probes are now running; this does not establish
active WAL, torn-primary or exhaustive crash qualification. The ACL v2 work
correction is independently source-approved and the prepared v16 snapshot
matches both reviewed files; host rechecks remain queued.

ACL v16 formatting passes but compilation stops because the new boundary test
references private parent helpers without super:: qualification. Fresh v17
corrects those test-only paths and includes all nine integrated NTFS files.
The combined five host checks are running
([results](/data/cache/partmgr-ext-acl-birth-host-checks-20261013-v17/result.json)).

Independent review revalidates the actual modern helper build and standalone
probe closure, including 213 compiler dependencies and 54 output artifacts.
All 18 profile/refusal probes pass; active native qualification remains open.
A separate native-qualification-modern optimized build is prepared for the next
Cargo slot, preserving the frozen count/xattr/metadata binaries.

The combined ACL v17 candidate passes all five host checks against 428
unchanged inputs. Independent review confirms the production work correction
and test-only helper qualifications. Root integrated exactly ten ACL paths and
verified all 428 current inputs against the passing snapshot
([binding](/data/cache/partmgr-acl-current-integrated-binding-20261013-v1.json)).
These checks do not establish native ACL crash qualification.

The separate modern optimized build now succeeds. Root rehashed its source
manifest, compiler artifact and build JSON, and confirmed that all three frozen
count/xattr/metadata binaries remain unchanged
([receipt](/data/cache/partmgr-modern-native-custom-profile-build-20261013-v2/receipt.json)).
The 90-case resource planner ran without `--execute` and failed while replaying
a descriptor with a UUID binding error. The xattr planner hit the same error
after 51,394 operation rows, at a header-only uncommitted descriptor. Both
planners also use conservative full-union bounds that already exceed their
configured file/byte ceilings on partial first cases; increasing the ceilings
or sampling would not complete qualification. A hashed diagnosis records the
evidence and required fixes
([diagnosis](/tmp/partmgr-modern-xattr-planner-failure-diagnosis-20261013-v1.json)).
Native acceptance and public modern write authority remain open.

The first bounded ACL native authoring attempt correctly stopped at its
whole-image byte proof: native `debugfs` changed the primary ext superblock
write-time field at byte 1072 to 1980-01-01, while sparse-super copies retained
their original value. The partial output and exact hashes are retained
([failure record](/data/cache/partmgr-ext-acl-native-authoring-failure-20261013-v1.json)).
That first proof correctly rejected the unaccounted timestamp change; the fresh
v6 proof below binds the deterministic field across all three block sizes.

The correction uses e2fsprogs' documented source path: its native close updates
`s_wtime` from `SOURCE_DATE_EPOCH`, which takes precedence over the older fake
time variable. Fresh ACL authoring v6 sets that environment value and proves
every sparse-super copy equals the fixed 2000-01-01 value before and after the
native operation. Independent source and wrapper reviews are closed. The fresh
bounded run completed 57 models (39 ordinary ACL cases and 18 child-birth
cases), 384 successful native commands and 1,054 output artifacts. The final
independent closure review rehashed all 84 preflight inputs, replayed 114
inventories and all 57 full-image proofs, and verified 190 fixed timestamp
fields. See the [fixture receipt](/data/cache/partmgr-ext-acl-native-oracle-20261013-v2/receipt.json),
[wrapper execution record](/data/cache/partmgr-ext-acl-native-authoring-wrapper-20261013-v2/execution.json)
and [independent closure review](/tmp/partmgr-ext-acl-native-v2-final-closure-review-20261013-v1/review.json).
This remains native physical fixture evidence only; mounted-kernel inheritance,
Rust crash recovery and public ACL writer qualification remain open.

Cached `InitializeFileRecordSegment` (opcode 2) redo/undo is integrated as a
read-only NTFS model. Independent source review accepts its cached-only scope,
redo-only LSN update and bounded no-effect behavior. The earlier five-check run
covered the archived 428-input worktree
([results](/data/cache/partmgr-ntfs-native-initialize-host-checks-20261013-v1/result.json)).
The four reviewed NTFS paths and then-current Cargo.toml/Cargo.lock are covered
by the full archived worktree binding
([binding](/data/cache/partmgr-current-integrated-binding-20261013-v1.json)).
The six additional cached-initialization boundary and provenance tests were
added without changing the existing test-file prefix. All five repository host
checks pass for the frozen snapshot of 472 partmgr inputs and 104 files from the
bound `virtdisk` path dependency
([results](/data/cache/partmgr-current-live-frozen-checks-20261013-v3/result.json),
[input manifest](/tmp/partmgr-live-frozen-host-checks-20261013-v3/manifest.json),
SHA-256 `a7e3ee109ac1f17e6e9d560b743901d448bed7b36f06e12b345a024bea65a343`).
Uncached initialization and durable NTFS publication remain open.

The original modern JBD2 planner runs stopped on an incomplete descriptor UUID
binding and conservative full-union resource bounds; configured caps remain
unchanged, and those planners have not been rerun. The private publisher now
invalidates descriptor headers, stages and verifies descriptor/data bodies,
then publishes and verifies descriptor headers before the commit header. Its
added writes, reads, barriers and work are included in generic, xattr and ACL
reservations. Exact-prefix tests cover committed destinations and bytes,
header/body failure cuts, and no-write refusal boundaries.

The corrected publisher and tests pass the repository host gates on a frozen
5,433-input partmgr/virtdisk source capture: formatting, all-feature Clippy and
tests, and no-default-feature Clippy and tests. The three corrected focused
regressions also pass. The source capture remained unchanged during checks
([input manifest](/tmp/partmgr-jbd-header-last-focused-compile-20261013-v5/manifest.json),
SHA-256 `5a30881597c704d548de0098f7036335e711d51d246476dfbea0dbc7f9f986b9`;
[host result](/tmp/partmgr-jbd-header-last-focused-compile-20261013-v5/host-checks-result.json),
SHA-256 `903e7e40da69de2216f4cd45faf303eee02d9e93e9ad62232f8af90f89354626`).
The full-source closure review found no blockers
([review](/tmp/partmgr-jbd-header-last-v4-full-closure-ntfs-independent-review-20261013-v1.json),
SHA-256 `529c8207ca3a715669d194b20a7f1f4f8b365e79016573da3fe61a313b4f969e`).
These are host checks only: native JBD qualification and planner reruns remain
open, so this does not establish native crash or filesystem recovery authority.
