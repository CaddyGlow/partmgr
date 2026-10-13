# Filesystem writes, checking, formatting, and expansion plan

Updated: 2026-10-13. Status: partial implementation; qualification gates remain open.

See the [implementation inventory and remaining gates](filesystem-maintenance-status.md)
for current implementation, source locations and explicit exclusions. The public
`std` classic-ext3 ordered session now provides append/create, truncate, hardlink
and namespace operations, plus manifest-five range overwrite within existing
EOF. Earlier operations have scoped native receipts; range overwrite passes all
five host checks and its source-bound offline native interruption gate;
adversarial verifier controls and independent rehash also pass. The later
manifest-six sparse extension has scoped host/native and adversarial qualification,
with independent final rehash, bound to its archived revision. Manifest seven
integrates unfollowed symlink create/target replacement/read/rename/unlink;
all five source-bound host checks pass
([365-source receipt](/data/cache/partmgr-maintenance-ext-symlink-checks-20261011-v5/result.json));
source-bound native interruption/recovery, adversarial controls and final rehash pass for the archived manifest-seven snapshot.
The integrated checkpoint includes private classic-ext user-xattr
lifecycle handling, mounted-kernel ACL comparison fixtures, and NTFS physical
traversal, checkpoint, transaction, dirty/open-name and target-observation layers,
ordinary-file attribute winner selection, physical run projection, source-ordered
dirty LCN maps, redo-start derivation and exact redo traversal with readonly
nonresident byte shadows and bitmap effects for the admitted operation classes,
with retained runtime targets and completed source reads. Private ignored xattr qualification
tests include persistence matrices, callback/resealed controls and resource planning.
The private modern KEEP_SIZE planner/controller and actual session regressions
are also integrated. The archived 428-source checkpoint passed all five host
checks
([source binding](/data/cache/partmgr-acl-current-integrated-binding-20261013-v1.json)).
The private ACL session now includes access/default changes, chmod, atomic
child creation with inheritance, owned cold recovery and bounded shared work.
Native ACL writer qualification and public promotion remain open.
These additions do not establish native xattr writer qualification or NTFS
recovery/write authority. Cached FILE deallocation, admitted shared undo effects and post-undo mirror
shadows are integrated as read-only models. Complete operation coverage, native
cache/I/O outcomes and durable publication remain open.
The cached FILE initialization opcode (redo/undo) is integrated as a read-only
model. The earlier 428-input host run passed all five checks, including the
then-current `Cargo.toml` and `Cargo.lock`
([source binding](/data/cache/partmgr-current-integrated-binding-20261013-v1.json)).
Uncached initialization remains unsupported.

The latest frozen host run passes all five repository checks for 472 partmgr
inputs plus 104 files from the bound `virtdisk` path dependency
([results](/data/cache/partmgr-current-live-frozen-checks-20261013-v3/result.json),
[input manifest](/tmp/partmgr-live-frozen-host-checks-20261013-v3/manifest.json)).
It includes six additional cached-initialization boundary and provenance tests
and the current forensic lint corrections. The manifest is the exact tested
snapshot; these host checks do not establish native NTFS publication or write
authority.

ACL authoring v6 now has a completed, independently rehashed native fixture set:
57 models, including 18 child-birth cases, with 1,054 retained artifacts and
full-image proofs across all three block sizes. The independent closure review
recomputed inventories, guest-derived ACL/mode expectations and the fixed
superblock write-time fields
([fixture receipt](/data/cache/partmgr-ext-acl-native-oracle-20261013-v2/receipt.json),
[closure review](/tmp/partmgr-ext-acl-native-v2-final-closure-review-20261013-v1/review.json)).
This is physical fixture-authoring evidence only; mounted-kernel inheritance,
Rust crash recovery and public ACL writer qualification remain open.
Modern preallocation native qualification remains open. Counter-repair and
inode metadata setter drafts remain outside the repository; their native
qualification gates remain open.
See the [current implementation checkpoint](filesystem-maintenance-status.md#current-implementation-checkpoint--2026-10-13)
for the distinction between integrated APIs, accepted evidence and draft work.
Modern ext4 mutation and transactional NTFS writing remain gated. Maintenance
contracts and scoped audit bridges alone confer no write authority.

## Required outcome

Deliver recoverable ext3/ext4 editing and complete NTFS read/write coverage,
including alternate data streams (ADS), ACLs, compression, EFS encryption, and
volumes with or without the USN change journal. Provide check, repair, format,
and expand APIs for every supported filesystem where its format and storage
profile permit the operation. Unsupported operations must explain the exact
format, feature, geometry, or backend restriction before performing any writes.

This document extends [FILESYSTEM_PLAN.md](../FILESYSTEM_PLAN.md). Preserve its
first priority: NTFS stable acquisition/snapshots, complete native metadata,
ACLs, and forensic access. This is a plan, not a declaration that the operations
are implemented or qualified. It authorizes no erasure or execution on user disks.

USN means the NTFS change journal. USN-disabled NTFS still requires correct
`$LogFile` transaction handling; disabling USN does not disable crash recovery.
EFS file encryption and BitLocker volume encryption are separate capabilities.
ADS writing is a required deliverable, including named streams on directories.
Timestamp, native metadata, ACL/security, and filesystem journal editing are
required across every target family wherever the native format supports them.
These requirements apply beyond ext and NTFS and remain part of family completion.

## Baseline and gaps

Reconcile these checkpoints against source before beginning each milestone:

| Area | Existing foundation | Work needed before public write claims |
| --- | --- | --- |
| Shared contracts | Public bounded maintenance contracts and scoped audit bridges; owned storage, budgets, cancellation and external undo | Complete diagnostic coverage, repair implementations, feature manifests and common operation dispatch |
| ext2 | Public classic builder/editor, fresh-file formatter and same-final-group geometry growth with scoped native evidence | New-group growth, broader format profiles, bounded repair and remaining maintenance integration |
| ext3/ext4 | Public manifest-seven classic-ext3 session integrates symlinks alongside ordered append/create/truncate, range overwrite, sparse extension, hardlink and namespace operations; explicit owned recovery; archived manifest-seven source-bound native/adversarial qualification and final rehash pass; private modern JBD/JBD2 work | Preallocation, modern public profiles, metadata/ACL operations, format/grow and remaining recovery gates |
| NTFS | DATA/ADS and bounded compressed readers, resolved ownership audit profile, security/USN decoding and bounded `$LogFile` inspection | Broader resolved ownership; active-window replay overlay and transactional writer; ADS/ACL/compression/EFS mutation; format/grow/repair and Windows qualification |
| Other families | Mixed public builders/editors and bounded readers; private work in some engines | Per-profile check/repair/format/expand contracts and evidence; do not infer availability from family names |

The support matrix is an inventory and may lag private development. Use
[ext journal work](filesystem-ext-journal-edit.md),
[NTFS priorities](filesystem-ntfs-priority.md),
[NTFS streams](filesystem-ntfs-streams.md), and the actual public exports to
establish the starting point. Preserve existing unrelated working-tree changes.

## Meaning of complete support

Maintain a versioned feature manifest rather than one `full_support` boolean.
Every feature has independent inspect, decode, preserve, create, edit, repair,
format, grow, and recovery status, with source-bound evidence and prerequisites.
Unsupported historical/vendor profiles stay visible; they are not silently
included in a general NTFS or ext4 claim.

For NTFS, the completion manifest must enumerate ordinary/resident/nonresident
streams, ADS, sparse allocation, compressed units, EFS, native names/collation,
hardlinks, attribute lists, all timestamp views, security descriptors, reparse
points, EAs, object IDs, quotas, change tracking, and reserved/system objects.
WOF/CompactOS, deduplication, TxF, and filter-owned reparse payloads need separate
preservation and mutation decisions. Opaque preservation alone is not writable
support. Any deferred feature prevents an unqualified full-support claim.

## Common API and execution model

Design illustrative interfaces first; adapt names to the current API without
introducing a second storage abstraction:

| Entry point | Inputs and result | Mutation rules |
| --- | --- | --- |
| `capabilities(profile, backend)` | Operation and feature matrix, geometry limits, key/device prerequisites and evidence scope | Read-only; separate native implementation from optional host-tool adapters |
| `check(source, options)` | Structured findings, locations/object identities, severity, scope, skipped features, completeness and recovery needs | Never repairs or replays into the source; bounded read-only replay overlay may be explicit |
| `plan_repair(source, report, policy)` | Exact proposed changes, data-loss risk, unrecoverable ambiguities, dependencies, estimated resources | Read-only; ambiguous ownership never resolved by guessing |
| `repair(owned_session, plan)` | Durable transaction/recovery outcome and post-check | Requires stable identity/generation and full preflight; independently restartable |
| `plan_format(target_geometry, options)` | Chosen native features, label/UUID policy, metadata layout, erase scope, bad-block and allocation-unit policy | Planning never writes |
| `format(owned_session, plan)` | Reopenable formatted filesystem and independent check report | Prefer unpublished new output; explicit replacement for existing content |
| `plan_expand(source, target_bytes, options)` | Current/target geometry, hard limits, metadata moves, required container/partition space, journal/scratch requirements | Read-only; reject unsupported feature combinations early |
| `expand(owned_session, plan)` | Durable native filesystem growth and post-check | Does not implicitly grow an image or partition; orchestrator applies the explicit order |

Separate `Check`, `Repair`, `Format`, `Grow`, and `Shrink` in the capability model
or an additive maintenance model. Existing `Build`, `Recover`, and `Resize` must
not imply them. Grow is filesystem geometry growth; extending one file is a
different operation. Shrink is separately planned and never inferred from grow.

All reports distinguish clean, inconsistent, recovery-required, unsupported,
incomplete due to limits, and I/O failure. A partial check cannot report clean.
Record findings even when a later scan hits a budget, with completeness explicit.
`chkdsk` may be a documented alias for `check`; repair requires an explicit mode.
Physical surface scans are optional backend-specific checks, separate from
logical consistency. Quick format and destructive surface initialization need
distinct policies and guarantees.

Owned sessions require exclusive access and a stable source generation. Bind
plans to volume identity, geometry/features, backend/region and metadata evidence;
revalidate before writes. Cancellation before mutation leaves bytes unchanged;
after mutation it returns a precise recovery obligation. Uncertain writes/flushes
retain a sticky recovery state. Bound all allocations, scan work, patch sizes,
log occupancy, scratch usage and retry counts.

Container growth precedes partition growth, which precedes filesystem growth.
A failure leaves a smaller filesystem inside a larger valid boundary. Shrink,
when supported, completes filesystem work before reducing the partition and
container. Preserve explicit durable commits and report each layer's outcome.

## Cross-family timestamp, metadata, ACL, and journal editing

### Required public operations

Expose inspect, plan, commit and post-check for each supported native operation.
Provide a common typed patch for portable fields and format-specific extensions
for fields that cannot be represented faithfully in the common model. Every
patch distinguishes unchanged, set and remove; missing input never means clear.
Allow atomic multi-field edits where the qualified transaction can provide them,
and report operation boundaries when a batch needs multiple transactions.

| Area | Required editing scope | Contract and acceptance |
| --- | --- | --- |
| Timestamps | Set each native creation/birth, modification, access, metadata-change and backup time that exists; select object, stream or native timestamp view explicitly | Preserve precision, range, timezone/offset encoding and unknown native bits; report unrepresentable values before mutation |
| Ownership and permissions | Numeric UID/GID, native owner/group SIDs or identities, modes, file/directory flags and supported security labels | Exact restore and policy-driven edits are distinct; qualify native privilege and access semantics |
| Extended/native metadata | Add/replace/remove xattrs, supported EAs, Finder/catalog fields, DOS flags, reparse metadata and other documented native fields | Preserve unrelated/unknown fields; regenerate dependent checksums, indexes and accounting; system-derived fields need typed invariant-preserving operations |
| ACL/security | Read/set/remove access/default ACLs, DACL/SACL, inheritance, masks and supported native ACE forms | Retain native semantics and absent/null/empty distinctions where applicable; do not translate incompatible ACL models silently |
| Volume metadata | Labels, supported volume identifiers, feature options, quotas/project settings and native configuration | Report identity/key/checksum/reference consequences; feature transitions are separately qualified operations |
| Transaction journal | Inspect status, validate, replay/recover, checkpoint, and supported create/enable/disable/resize/relocate/configure operations | Native lifecycle operations must preserve transaction ordering, volume binding and recovery invariants; advertise each operation separately |
| Change/history journal | Inspect and supported lifecycle/configuration operations, plus native records for ordinary edits | Distinguish USN-style change tracking from transaction recovery and format-specific history mechanisms |

Metadata-change timestamps may be maintained by the native implementation or
overwritten by a later mount. Record exact raw-image restore separately from
mounted-host edit semantics. Do not claim persistent arbitrary ctime editing
through a host API that cannot provide it. Explicit timestamp restore policy
controls whether an edit updates related timestamps, preserves them, or restores
specified native views; all invariant-required updates remain visible in the plan.

For timestamp conversions, validate native epoch, signedness, subsecond units,
range and local-time encoding; never silently clamp or use the host timezone.
Accept explicit native/raw values when a wall-clock representation would lose
information. Preserve NTFS SI and each FILE_NAME view separately and qualify any
supported ADS timestamp behavior from native evidence rather than inventing fields.

ACL editing includes inheritance on create/move, default-to-access propagation,
mask recalculation, shared descriptor/xattr lifetime, hardlinks and native
effective-access checks. Unknown ACEs may be preserved exactly; interpreting or
rewriting them requires a qualified semantic profile. Filesystems without a
native ACL model expose `Unsupported`; sidecar metadata is a separate export
format and cannot be reported as native ACL support.

Journal editing means typed management and native transaction/change-record
generation. Direct arbitrary log-byte modification belongs to a separate forensic
patch workflow and does not establish a valid journal. Never discard committed
transactions to make a dirty filesystem appear clean. Journal disable/removal
requires supported clean checkpoint and native feature transitions; reset or
reinitialization with data loss is an explicit repair proposal. External journals
require ownership and identity validation for every participating device.

### Family-specific delivery map

The entries below are planning scopes. P0 must establish exact supported native
fields and journal operations from pinned references and native fixtures before
implementation; no row grants a blanket feature capability.

| Family | Timestamp / metadata / ACL scope | Journal scope |
| --- | --- | --- |
| FAT12/16/32, VFAT | Native directory times, DOS flags and volume label; precision/timezone rules explicit; native ACL unavailable in the standard profile | No standard native transaction/change journal; external undo stays separate; transactional variants separately researched |
| exFAT | Native times and timezone fields, attributes and label; standard profile has no native ACL | Dirty-state fencing/external undo; TexFAT is an independent transactional profile |
| ext2/3/4 | Native inode times, UID/GID/mode/flags, xattrs, POSIX access/default ACLs, labels and supported quota/security metadata | ext3/ext4 JBD/JBD2 lifecycle and replay; ext2 journal conversion requires a separately qualified format transition |
| NTFS | SI/FILE_NAME time views, flags, EAs/reparse/object metadata, owner/group and full supported security descriptors; ADS-aware operations | `$LogFile` recovery/lifecycle and USN on/off/configuration independently qualified |
| XFS | Native inode times, IDs/modes/flags, xattrs/ACLs, project/quota metadata and label | Native log replay/checkpoint/configuration and internal/external placement only where supported |
| Classic HFS | Native catalog/volume times, Finder information and flags; native ACL availability determined by the exact profile | Standard classic profile has no transaction journal; external recovery remains explicit |
| HFS+/HFSX | Catalog times, BSD ownership/mode/flags, Finder metadata, attributes and native security/ACL representation where present | Journaled and nonjournaled profiles; native replay and supported lifecycle transitions |
| APFS | Native inode times, ownership/mode/flags, xattrs and ACL/security representations; volume metadata | Native COW checkpoints, transaction identifiers and history management; do not impose a JBD-style journal abstraction |
| JFS | Native times, ownership/mode, EAs and ACL/security representations for qualified native profiles | Native inline/external log, replay/checkpoint and supported lifecycle/configuration |
| JFFS2 | Native inode times, ownership/mode and supported xattr/ACL node formats | Append/version reconstruction and GC recovery; no invented separate transaction journal |
| UDF | Revision-specific native times, permissions, ownership, EAs and supported ACL/security forms | Revision/partition-specific integrity and update mechanisms; qualify native equivalents individually |
| ISO9660/Joliet/Rock Ridge | Descriptor/directory times and supported extension metadata, ownership/modes and declared security extensions | Rebuild or supported new-session publication; no generic in-place journal management |

### Implementation and completion gates

1. Extend capability queries with per-field timestamp/metadata access, native ACL
   model and individual journal lifecycle operations. Separate unsupported native
   semantics from implemented-reader-only and not-yet-qualified writer states.
2. Reuse owned sessions and feature-specific transaction planners. Validate the
   whole requested patch before mutation, including value representation,
   privileges, shared metadata, key dependencies and journal space.
3. Implement preservation-first updates for every public writer, then native
   timestamp/metadata setters, ACL mutation and supported journal management.
   A formatter must initialize these fields with explicit caller/default policy.
4. Check/repair must validate edited metadata, ACL bindings, checksums and journal
   state. Format/expand and namespace/payload writes must preserve unrelated
   values and apply declared inheritance/timestamp/change-record policies.
5. Add native before/after field comparisons and effective ACL checks for regular
   files, directories, symlinks where applicable, hardlinks and native streams.
   Include timestamp limits/precision, unknown fields/ACEs and shared metadata.
6. Run every mutation through failure/cancellation/restart cuts, including ACL
   index growth and journal enable/disable/resize/replay interruption. Validate
   subsequent native mount/edit and partmgr reopen without silent repair.
7. Attach source-bound receipts per family/field/operation. A family remains
   incomplete while a native-supported required edit or journal lifecycle
   operation lacks implementation or qualification; document genuine native
   restrictions with a precise reason.

## Milestone 0: feature inventory and qualification design

1. Inventory actual public and private implementations and exact source-bound
   receipts; classify stale, partial, failed, and accepted evidence.
2. Pin primary disk-format references and implementation cross-check revisions.
   Record unresolved NTFS specification details as research tasks with native
   fixture experiments, rather than inventing fields or log semantics.
3. Publish sector/block/cluster sizes, address widths, inode/record sizes,
   supported feature bits and maximum geometry for each initial profile.
4. Specify maintenance reports, plan binding, durability outcomes, and capability
   compatibility. Decide public enum changes according to crate version policy.
5. Create independent fixture generators and oracle protocols before changing
   production writers. Define numeric workload/resource limits before release.

Exit: reviewed profile manifests, API design, dependency graph and executable
qualification protocols. No unsupported profile becomes writable at this stage.

## Milestones E1–E5: ext3/ext4 writes

### E1. Promote the native transaction foundation

Audit private JBD/JBD2 parsing, legacy/v2/v3 checksums, descriptor/data/revoke/commit
records, escape handling, ring wrap, transaction ordering and sequence rollover.
Separate replay of native foreign transactions from any stronger integrity
constraints used by partmgr-authored transactions. Define precisely which dirty
volumes can be recovered; unsupported valid native logs cannot be called corrupt.

Close outstanding bootstrap, torn activation, replay-overlay ownership, repeated
transaction, checkpoint and every-cut native gates. Check the private legacy
integrity-footer design against Linux replay without requiring it on foreign logs.
Only then expose a production owned journal session; mutable storage must never
implement the immutable reader contract.

Initial public profiles: bounded classic ext3 with internal journal, then modern
checksummed ext4 at qualified 1/2/4 KiB geometries. Document data durability mode
separately from metadata atomicity. Ordered data publication is the initial
target; writeback and full data journaling require separate evidence.

### E2. Complete ordinary mutation

Implement and qualify create/mkdir, range overwrite, append, sparse extension,
truncate, allocation/preallocation, rename and cross-parent move, hardlink,
unlink and empty-directory deletion. Cover indirect and extent mappings, extent
split/merge/depth changes, HTree split/growth, allocation-group boundaries,
uninitialized maps, inode reuse/generation, link counts, sector accounting,
checksums, free counters and orphan handling. Preserve unrelated metadata.

Define replacement and rename collision semantics explicitly. Recursive deletion
is a sequence of bounded operations unless a larger atomic contract is proven.
Support symlink creation/target changes and supported special inode types under
explicit policies; do not follow symlinks during a namespace mutation by default.

### E3. Metadata, ACLs and advanced features

Add UID/GID, mode, all supported timestamp encodings, flags, xattrs and POSIX
access/default ACL edits, inheritance and mask semantics. Handle shared external
xattr blocks, reference counts, checksums and allocation lifetimes atomically.
Security labels and file capabilities need exact preservation plus explicit edit
policies; they must not be synthesized from generic metadata.

Expand separately to high addresses/64-bit allocation, bigalloc, inline data,
casefold, orphan-file variants, external journals, fast commits, quotas and
project IDs. Every combination requires an allowlist and negative controls.
For ext4 fscrypt, separate ciphertext-preserving capture from key-backed plaintext
read/write and encrypted-name policies. Verity-protected data needs native
immutability handling, not ordinary replacement. ext3/ext4 native compression is
not promised; optional nonstandard implementations require distinct profiles.

### E4. ext formatting and expansion

Extend the existing classic builder into explicit ext3/ext4 format profiles:
native journals, checksums/seeds, group descriptors, backup superblocks, inode
tables, reserved metadata, resize/orphan structures and caller-selected features.
Reopen, audit and check every format result before publication.

Grow first within an existing group, then add groups and handle backup metadata,
descriptor capacity, lazy/uninitialized tables, counters and address limits.
Plan all relocated metadata and journal capacity before mutation. Qualify native
e2fsck and mount behavior after normal growth and every restart boundary. Offline
owned growth is first; online growth through a mounted host adapter is separate.

### E5. ext checking and repair

Combine structural, checksum, allocation, directory/link, xattr, journal, orphan
and backup metadata checks. Start repair with unambiguous redundant metadata,
replayed committed transactions and recomputable counts. Add bitmap rebuilding,
orphan reconnection and directory/index reconstruction only after ownership and
data-loss policies are explicit. Cross-linked payload and contradictory inode
ownership require a reviewable resolution policy, never arbitrary reclamation.

Exit for each ext milestone: native e2fsprogs validation, Linux mount/read/write
round trips, complete payload and metadata comparisons, bounded malformed-input
tests, interruption/recovery matrix, and source-bound receipts for each profile.

## Milestones N1–N8: NTFS complete read/write

### N1. Finish authoritative read and ownership models

Extend existing MFT bootstrap and attribute resolution to whole-volume allocation
and reference audits, including extension records, index allocation, sparse maps,
initialized-size semantics, every named stream and reserved/system allocation.
Complete native `$UpCase` collation and directory `$I30` traversal/split models.
Track FILE sequence numbers, base/extension references, hardlink identity, all
SI/FILE_NAME timestamp views, stream names and opaque metadata provenance.
Resolve selected-tree exclusions explicitly before claiming complete capture.

Keep VSS acquisition/stability, security resolution and forensic work on the
existing priority path. A readable volume is not automatically safe to mutate.

### N2. `$LogFile` recovery and durable transaction writer

Research and implement supported restart areas, log pages, fixups, LSN ordering,
transaction tables, redo/undo operations, checkpoint/restart and log wrap. Define
version-specific allowlists using Windows-authored fixtures and native recovery.
Support foreign dirty-volume recovery only for decoded operation classes;
unknown log operations produce an explicit unsupported recovery outcome.

Build a read-only replay overlay and audit the resulting state before replaying
into owned storage. Implement native write-ahead logging, commit, home updates,
checkpoint and restart with correct write/flush barriers. Cover `$MFT`,
`$MFTMirr`, `$Bitmap`, directory indexes, attribute lists and system counters.
An external undo protocol may aid development but cannot substitute for a
Windows-compatible `$LogFile` writer in the final contract.

### N3. Ordinary files, namespace and ADS writes

Implement unnamed and named DATA through the same validated stream mutation
engine. Required ADS operations:

- Enumerate/open by exact native UTF-16 name and owning FILE identity; distinguish
  a missing stream from an existing zero-length stream and the unnamed stream.
- Create, replace ranges, append, extend, truncate, rename and delete named DATA
  on files and supported directory objects. Keep stream rename separate from
  directory-entry rename; reject collisions under qualified native collation.
- Transition resident/nonresident storage, split/grow attribute lists and allocate
  extension records without losing unrelated streams or metadata.
- Maintain logical, initialized and allocated sizes; zero newly exposed bytes;
  support sparse holes and runlist split/merge across cluster/record boundaries.
- Preserve ADS across hardlinks, namespace moves, complete capture and restore.
  Deleting one hardlink retains every stream; deleting the final object releases
  all owned stream allocations under the recovery protocol.
- Exercise unnamed and multiple named streams with distinct sparse, compression
  and encryption states where Windows permits them. Reject forbidden states
  before writing; do not infer stream state from the file's default DATA alone.

Also implement create/mkdir, replace, hardlink, move/rename, unlink, symlinks and
qualified reparse/EA/object-ID operations. Update all required native references,
indexes, flags and timestamps. Writes must not require extracting or rebuilding
the whole image for an ordinary stream operation.

### N4. USN enabled, disabled and lifecycle management

USN policy is explicit: preserve the volume's state by default, or request a
separately authorized create/configure/delete operation. Ordinary editing of a
USN-disabled volume must not create a journal. With USN enabled, maintain `$J`,
`$Max`, journal identity, next/lowest valid USNs, sparse retention and versioned
record framing. Qualify native lifecycle/deletion-in-progress states before edits.

Generate reason/source/close records and old/new rename pairs according to
Windows behavior, including named-stream data/size changes and security changes.
Update per-file USN metadata and transaction ordering with `$LogFile`. Specify
recovery behavior so replay does not expose invalid offsets, duplicate identity
reuse or silently skipped committed changes. Implement retention, journal-full
handling and identity changes; do not model `$J` as a guessed circular array.

Exit: run every N3/N5/N6/N7 operation with USN absent and enabled; compare native
Windows journal queries and incremental-consumer behavior across commit/restart.

### N5. ACL and security mutation

Implement exact owner/group, DACL/SACL, control bits, ACE order, inherited ACEs,
object-specific ACEs and absent/null/empty distinctions. Preserve unknown ACE
payloads without inventing semantics. Expose exact restore separately from
policy-driven inheritance/recalculation and access checks.

Maintain `$Secure:$SDS`, `$SII`, `$SDH`, native hashes, redundant copies, aligned
placement and index growth. Atomically bind security IDs to all relevant FILE
records. Define deduplication, descriptor reuse and retention semantics from
native evidence; do not reclaim shared descriptors using guessed reference counts.
Windows adapters report required privileges and native access-check semantics.

Exit: Windows retrieves identical descriptors, owner SIDs, ACL distinctions and
inheritance results; SACL tests exercise required privileges; chkdsk remains clean.

### N6. Compression and sparse compressed streams

Implement bounded native LZNT1 decoding/encoding and compression-unit mapping,
including compressed, uncompressed and all-zero units, fragmented runs, partial
units and mixed sparse allocation. Partial writes read/decode/re-encode only the
affected units and transactionally publish new allocation and sizes.

Qualify incompressible data, unit-boundary writes, initialized tails, truncation,
attribute extension and named streams. Reject malformed expansion before
allocation. Native NTFS compression and WOF/CompactOS codecs are separate work;
inventory WOF providers/reparse metadata and qualify XPRESS/LZX or external-source
handling independently before claiming their mutation support.

### N7. EFS and encrypted writes

Provide three explicit operations: preserve opaque encrypted objects without
keys, raw encrypted backup/restore, and plaintext read/write using authorized
key material. Preserve EFS metadata, recipients/recovery agents and stream
identity; support new encrypted files, range changes, truncate, key/recipient
updates and conversion only for qualified native profiles.

Start with Windows EFS service/API-backed qualification, then implement portable
on-disk crypto profiles where pinned specifications and independent fixtures are
sufficient. Host service support does not establish portable raw-image support.
Keys come through explicit providers; missing/wrong keys fail without writes.
Keep secrets out of logs/receipts; bound and clear secret buffers where feasible.
Account for plaintext in staging, journals and recovery artifacts.

Native NTFS compression and EFS cannot be enabled together on the same file;
validate Windows-permitted file/stream combinations rather than promising every
cross-product. Test EFS + ACLs + ADS + USN for each valid combination. BitLocker
is an outer envelope with its own unlock/write/durability gates; filesystem EFS
support does not establish BitLocker write safety.

### N8. NTFS check, repair, format and expansion

Check boot/backup geometry, MFT/mirror and fixups, all attributes/runlists,
ownership/bitmap accounting, native indexes, link/sequence references, security,
system metadata, `$LogFile`, USN, compression and EFS metadata. Without keys,
report encrypted-content verification as unavailable rather than fully checked.

Repair begins with validated redundancy and recomputable counts/indexes, then
adds journal recovery, lost-object reconnection, bitmap/security repairs and
explicit crosslink resolution. Preserve original evidence and provide exact
data-loss reporting. Do not advertise parity with Windows chkdsk until the
versioned corruption corpus and native behavior establish the claimed scope.

Format creates a Windows-mountable NTFS profile with native boot/backup metadata,
MFT/mirror, reserved files, indexes, bitmap, upcase, security, log and required
volume metadata. Support labels, cluster/sector geometry, serials and an explicit
USN on/off policy. Reopen/audit before publication; qualify quick/full modes.

Expand updates native geometry, bitmap growth/mapping, backup boot placement and
all affected system allocations using the qualified log protocol. Keep unrelated
streams/security/encryption exact. Cover allocation pressure, metadata relocation,
large geometry boundaries and repeated growth. Shrink is a separate future
capability with relocation and immovable-object constraints.

## Maintenance coverage for every family

These are delivery targets and research gates, not current capability claims.
Every row needs a precise feature/geometry/backend profile and native evidence.

| Family | Check and repair work | Format work | Expansion work |
| --- | --- | --- | --- |
| FAT12/16/32, VFAT | Copies/active FAT, chains, lost/crosslinked clusters, LFN, FSInfo, backups; explicit salvage policy | Existing builder plus maintenance options/native variants | FAT capacity, root layout, data-start relocation, counts/backups; reject or explicitly convert FAT variants |
| exFAT | Boot copies, bitmap/FAT ownership, upcase, entry checksums, valid-data state | Existing builder plus explicit geometry/options | Bitmap/FAT capacity, cluster heap and boot updates; TexFAT separate |
| ext2/3/4 | E1–E5 with per-feature journal, ownership and ACL checks | Classic and journaled/checksummed profiles | Within/across groups, descriptor capacity and backup placement |
| NTFS | N1–N8 including logs, ADS, security, compression and encrypted metadata | Complete native system layout; USN policy | System metadata relocation/capacity and backup geometry |
| XFS | AG trees, reverse maps/refcounts where enabled, log replay, indexes and quotas | Native AG/log/system layout | Research/qualify AG growth and supported offline or native mounted execution; no inferred shrink |
| Classic HFS | MDB copies, bitmap, extents/catalog trees and forks | Native bounded formatter | Investigate allocation-block and bitmap/catalog limits; support only proven relocation profiles |
| HFS+/HFSX | Headers, allocation, catalog/extents, both forks, attributes and journal | Extend current builder profiles | Separate volume geometry growth from current file/fork resize; metadata-file relocation and alternate header |
| APFS | Container/volume checkpoints, spaceman, references, clones/snapshots and recovery | Existing bounded authoring, then broader native profiles | Container/store growth and volume quotas/reserves are separate operations; multi-store/encrypted variants gated |
| JFS | Inode/block maps, dtree/xtree, log and ownership | Native aggregate/fileset/log creation | Map/IAG/control-tree growth, log placement and aggregate geometry; native mounted execution separately qualified |
| JFFS2 | Node CRC/version history, reachability, ownership and flash recovery | Existing logical-NOR builder plus supported codecs | Add declared eraseblocks through valid backend geometry changes; physical NAND/OOB/ECC and bad-block policy separate |
| UDF | Revision-specific descriptors, maps, allocation, links and redundancy | Extend libmkiso adapter profiles | Research rewritable/VAT/sparable/metadata partition profiles; new session or rebuilt output distinguished from in-place growth |
| ISO9660/Joliet/Rock Ridge | Descriptor/extent/namespace/extension checks; repair usually produces new output | Existing libmkiso staged authoring | No generic in-place grow promise; rebuild or explicit multisession authoring when medium/profile supports it |

For a format that cannot perform an operation, expose a stable `Unsupported`
reason and, where useful, a separate rebuild/migration proposal. Increasing the
backing file alone is never reported as filesystem expansion. Read-only engines
can initially expose check; format/repair/grow stay unavailable until qualified.

## Validation and release gates

For each milestone/profile, require all of the following:

1. Independent fixtures authored by native tools/OS, plus malformed and boundary
   fixtures independently assembled from the pinned format model.
2. Full file/ADS/fork payload comparison and native namespace, hardlink, ACL,
   timestamp, xattr/reparse, sparse/compression/encryption metadata comparison.
   Validate every object, not a sample or only a tool's zero exit status.
3. Every write, flush, readback and publication cut with torn/short/full failures,
   failed flush both with and without persistence, retained/discarded volatile
   writes, cold restart and interrupted recovery. Assert allowed old/new states
   and recovery obligations; never demand data atomicity beyond the contract.
4. Cancellation, exhausted budgets, full filesystem/log/scratch, wrong source,
   stale plan/handle, concurrent-source changes and unknown features. Rejected
   preflight and malformed recovery cause zero writes.
5. Native cross-operation testing: partmgr writes → native checks/mount/reads →
   native edits → partmgr reopen/audit. Run checking before any native repair;
   preserve images and logs if the native OS changes them during mount/replay.
6. NTFS Windows gates on disposable copies: chkdsk validation and explicit repair
   experiments, stream APIs/PowerShell inventory, security APIs, compression,
   EFS/cipher/raw backup APIs, fsutil USN queries, native format/extend comparison,
   crash replay and complete encrypted-file plaintext validation with keys.
   Linux ntfs-3g/TSK evidence supplements Windows evidence and cannot replace it.
7. ext e2fsck/debugfs/dumpe2fs checks and native Linux mount/replay, including
   foreign journal transactions and repeated operations after recovery.
8. Raw and supported QCOW2 bounded-region backends, nonzero offsets, sector
   geometries, untouched canaries and backend-specific durability limits.
9. Numeric benchmarks for small random writes, ADS operations, fragmented maps,
   ACL lookup/edit, compressed-unit writes, scan memory, log wrap, format and
   grow. Record warm/cold conditions, I/O amplification and durable throughput;
   no ordinary update may silently become a whole-image rewrite.
10. Immutable receipts binding exact source, binaries, tools, fixture parameters,
    model hashes, image before/after hashes, commands, exits and complete outputs.
    A changed implementation requires fresh evidence for affected claims.

Required Rust checks for implementation changes:

```text
cargo fmt -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

Retain applicable no-default-feature, portability and integration checks from
the existing plan. Host tests do not establish native Windows servicing/capture,
physical flash, power-loss durability or firmware boot. QEMU/OVMF boot remains a
separate integration gate. This documentation change itself adds no runtime code.

## Delivery order and completion tracking

| Stage | Deliverables | Dependency / exit |
| --- | --- | --- |
| P0 | Inventory, manifests, common maintenance design, qualification corpus | Baseline reviewed; no capability overclaims |
| P1 | NTFS complete-read/security/acquisition priority closure; common read-only check reports | N1 and prior priority gates |
| P2 | Public ext journal foundation and ordinary writes; NTFS log foundation | E1/E2 and N2 independently qualified |
| P3 | NTFS files/namespace/ADS and both USN states; ext metadata/ACLs | N3/N4 and E3 baseline; native fault gates |
| P4 | NTFS ACL edits, compressed streams and EFS read/write | N5/N6/N7 with valid combination matrix |
| P5 | ext/NTFS format, expand, bounded repair | E4/E5 and N8; geometry/recovery gates |
| P6 | Remaining family maintenance, timestamp/metadata/ACL/journal editing and broader feature profiles | Per-row and per-field native/recovery acceptance; ongoing full-support gap closure |

This is a dependency order, not a calendar estimate. Estimate each stage only
after P0 identifies the unresolved disk-format research and qualification scope.
No milestone is complete merely because an API exists or unit tests pass.

Track each task with owner, exact profile, prerequisite, implementation status,
portable result, native result, fault result, benchmark result, evidence URI/hash,
and remaining exclusions. Update the support matrix only after its exact operation
gates pass. Keep this plan linked from the main plan so future work follows the
USN-enabled/disabled, ADS-write, compression, encryption, cross-family
timestamp/metadata/ACL/journal editing and maintenance scope.

## Primary references

Consulted 2026-10-10; pin revisions and archived hashes before fixture acceptance.
These references are not a complete NTFS on-disk specification.

- [Linux ext4 structures](https://docs.kernel.org/filesystems/ext4/),
  [JBD2 journal](https://docs.kernel.org/filesystems/ext4/journal.html), and
  [fscrypt](https://docs.kernel.org/filesystems/fscrypt.html).
- [Microsoft change journals](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journals)
  and [change journal records](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journal-records).
- [Microsoft file streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams),
  [compression](https://learn.microsoft.com/en-us/windows/win32/fileio/file-compression-and-decompression),
  and [file encryption](https://learn.microsoft.com/en-us/windows/win32/fileio/file-encryption).
- [Microsoft chkdsk](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chkdsk)
  and [extend](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/extend).
- [Existing specification ledger](filesystem-specifications.md) for other families.
