# Native ext journal editing work

The `std` build now exposes `fs_ext::ExtJournalSession`, an owned ordered
classic-ext3 surface for regular-file append/create/truncate/range overwrite/sparse extension and journaled directory
creation, rename/move, hardlink creation, file unlink and empty-directory removal,
plus exact unfollowed symlink creation, target replacement, reading, rename and
unlink. Manifest version seven admits Linux revision-one filesystems with 128-byte inodes, 1/2/4 KiB blocks,
exact compatible/incompatible/read-only feature words 4/2/1 (RECOVER is permitted
only as the recovery-state bit), and an internal checksumless journal without
REVOKE and with first block one. File handles and reads are bound to the owner and
session generation; mutation and recovery invalidate prior handles. Explicit
owned recovery checks the replayed profile before writes and retains
`NeedsRecovery` through post-recovery profile, source and cancellation checks.
Foreign dirty logs are not an automatic fallback. Mutable storage never becomes
an immutable reader, and the caller must ensure exclusive backend access.

The earlier manifest-one public-session host checks passed at
`/data/cache/partmgr-maintenance-ext-public-session-checks-20261011-v2/result.json`,
including six public consumer tests. Public ordered v2 and renewed private
fulljournal v10 native gates pass for their bound source snapshot. Historical
private receipts retain their original scope. Broader ordered operations,
modern profiles, metadata/ACL editing and the complete maintenance plan remain
unfinished; E1 is not declared complete.

The existing classic `ExtEditor` retains its external-undo contract. Broader
checksum, extent, HTree and modern namespace engines remain private. Their earlier
profile receipts do not widen the public ordered capability.

The bounded scanner handles legacy, checksum-v2 and checksum-v3 records, ring wrap, escaped data, committed revocations and incomplete transaction tails. The private writer supports native v2/v3 checksums and a separately bound owned legacy profile. Legacy publication preserves the native no-checksum feature bits and uses a SHA256 integrity footer in kernel-ignored commit padding; the owned recovery path rejects foreign unsealed legacy transactions. This footer is not a native journal checksum feature or an authentication claim. Publication durably clears the future commit header, writes and verifies descriptor/data plus the commit body, then publishes its twelve-byte header and verifies the complete commit. A torn header cannot expose a body that has not already passed its durable barrier. Both record count and work, including duplicate/revocation comparisons, consume explicit ceilings; retained maps and redo buffers use shared leases. Whole transaction validation precedes any authorized home-block replay.

A separate private foreign-journal preflight now uses the native scanner without
the owned preparation or legacy footer requirement. It validates the original
active journal header and checksum before normalizing an inactive header solely
inside the replay overlay. Actual native start and sequence fields govern the
scan. The complete overlay ownership audit must pass, including unchanged journal
inode and allocation mapping. The returned plan borrows exclusive storage,
retains its original controls and leased replay/audit evidence, and rechecks
length, controls and cancellation without writing or implementing `ReadAt`.
Known unadmitted journal feature profiles return unsupported outcomes.

The private owned session also admits cold storage through `open_for_recovery`.
Admission reads bounded bootstrap geometry and retains `NeedsRecovery`, even
for a clean image. Only explicit owned recovery followed by a fresh complete
ownership audit and final length/cancellation checks publishes `Ready` and file
handles. This entry point requires exclusively owned partmgr-authored recovery
storage; it does not select foreign recovery automatically. Backend errors,
including backend-defined format-like error kinds, remain fatal during initial
clean inspection instead of selecting the owned bootstrap fallback. Tests cover
read-only admission, late backend/cancellation/length failures, resource refusal
and foreign dirty-log refusal.

Renewed private fulljournal classic-ext3 qualification passed at
`/data/cache/partmgr-ext-owned-release-binding-20261011-v10/result.json`, with
the native receipt under `positive/qualification.json`. The optimized library
test covers 1,320 modeled write/flush interruption cases and 121 distinct
persisted images across 1/2/4 KiB, 128-byte-inode profiles. Extension crosses the
direct-to-single-indirect allocation boundary. Independent e2fsprogs replay
must match cold owned recovery across every byte outside independently decoded
journal data, including journal mapping metadata and superblock timestamps.
Fixture tools use a fixed clock; timestamp bytes are not masked.

The same session also performs replacement, rename, truncate, create and delete;
each resulting image receives native consistency, complete payload and preserved
unrelated inode/hardlink checks. The receipt retains 817 commands and source,
binary, tool and artifact bindings; missing-source, stale-source, reused-output
and altered-verifier controls fail. Earlier failed attempts remain retained.
This is offline recovery of modeled persisted bytes, not mounted-kernel or
hardware-crash evidence. It does not cover interruption of every repeated
operation, modern checksummed/extents profiles, ACL/xattr editing, or ordered
data semantics; the public ordered receipt below qualifies that separate policy.

Replacement and planned mutation now retain `NeedsRecovery` through fresh
post-transaction length and cancellation checks. Cancellation inside the last
backend length callback cannot publish `Ready`; a backend error or changed
length at that boundary also retains recovery state and the original cause.
The regression compares the complete committed image and write count, then
requires clean explicit recovery without additional writes. Removing only the
new guards reproduces the old erroneous success; that controlled regression is
retained at
`/data/cache/partmgr-ext-session-ready-regression-20261011-v1/result.json`.

All five repository host checks pass for the public-session 346-file source snapshot at
`/data/cache/partmgr-maintenance-ext-public-session-checks-20261011-v2/result.json`.
These checks cover formatting, strict all-target/all-feature Clippy, all-feature
host tests and the additional recorded target checks. Host checks do not
establish native replay, mounted crash behavior or firmware behavior. The separate
source-bound native gates below retain their exact policy scopes.

The classic allocation planner now retains private ordered-data evidence for
regular-file creation and extension. Each fresh-data token is tied to the
planner, owner/generation, native inode generation and logical block. Append
roles distinguish an existing EOF suffix from newly allocated whole blocks;
directory bodies, indirect blocks and other metadata remain outside those roles.
The final prospective ownership audit and regular-file mapping check share one
source-bound decoder. Projection lookups, sorting and role comparisons consume
finite planning work and preserve cancellation and backend causes. Independent
1/2/4 KiB tests cover tail-only and aligned appends, empty files, direct-to-indirect
allocation, creation, cross-planner token refusal and prewrite resource failures.
A separate private ordered controller now consumes this sealed evidence for
classic regular-file append and creation. The existing fulljournal controller
remains separate. Before its first write, the ordered path completes source and
generation checks, bounded allocation, combined prospective ownership audit,
metadata encoding and ring/physical-footprint/work preflight. It durably publishes
preparation, activation and the filesystem recovery fence before writing file
data. Existing EOF writes affect only the exact suffix; the old visible prefix
is preserved. Fresh regular data and suffix writes are flushed and their complete
containing blocks read back before mutation commit publication. Mutation redo
contains metadata only; directory bodies, allocation maps and indirect blocks
remain metadata.

Independent host fixtures at 1/2/4 KiB cover 444 immediate-persistence write/flush
interruption cases with cold owned recovery, metadata-only redo, exact EOF
suffixes and old-or-new visible outcomes. They also check creation, unsupported
profiles, resource refusal and sealed owner/generation binding. This is modeled
host evidence. The public source-bound native gate for append and create
passed for its archived source snapshot; subsequent private namespace changes require renewed native qualification. It requires independent e2fsprogs replay, native payload/namespace checks,
exact new-state homes and an independently derived old-state mask limited to
originally free regular data blocks and the old EOF suffix. Journal mapping
metadata remains in the exact comparison; only journal data is excluded.

The public ordered receipt is
`/data/cache/partmgr-ext-ordered-release-binding-20261011-v2/result.json`, with
native evidence under `positive/qualification.json`: 2,448 modeled cuts,
209 distinct persisted preimages, 1,354 recorded commands and nine separately
checked same-owner append/create/append-created snapshots. The entire ordered
cut/recovery/read path uses the public API. The verifier also
independently decodes baseline journal descriptors for all six block-size/operation
profiles and rejects regular-file data redo. Three retained prior-fulljournal
baselines fail this policy check at
`/data/cache/partmgr-ext-ordered-redo-negative-20261011-v2/result.json`.
The final rehash at
`/data/cache/partmgr-ext-public-session-final-rehash-20261011-v1.json` verifies
202 compiled sources per native gate against the workspace at that receipt, 3,026
fulljournal and 4,815 ordered outer artifacts, and all 346 host source hashes.
Both ordered and fulljournal release bindings reject missing/stale sources,
reused output and altered verifiers. These remain offline modeled persisted-byte
experiments, not mounted-kernel or hardware-crash evidence.

The `std` public `fs_ext::ExtJournalSession` now declares profile manifest
version seven. Its filesystem allowlist is unchanged: Linux revision one,
128-byte inodes, 1/2/4 KiB blocks, feature words 4/2/1 with transient RECOVER,
and an internal checksumless journal without REVOKE and first block one.
Alongside ordered regular-file append/create/truncate, `write_at` and `extend_sparse`, it exposes `create_directory`,
`rename`, `hard_link`, `unlink_file`, `remove_directory`, `create_symlink`,
`replace_symlink_target`, `unlink_symlink` and `read_symlink`. The manifest-seven
symlink integration passes all five source-bound host checks; source-bound native interruption/recovery, adversarial controls and final rehash pass for the archived manifest-seven snapshot.
The [current implementation checkpoint](filesystem-maintenance-status.md#current-implementation-checkpoint--2026-10-12)
also distinguishes unintegrated preallocation, counter-repair and NTFS drafts. Names are exact bytes; creation
uses explicit native metadata. Rename refuses existing destinations and cycles.
Deletion requires explicit native time, nonzero and at least the inode count;
source-owned planner kind guards distinguish regular unlink from empty-directory
removal before publication. No recursive deletion or payload wiping is implied.
Successful mutation/recovery invalidates handles; errors can conservatively
retain `NeedsRecovery`. Physical controller and planner authority remain private.

The sealed classic namespace controller accepts mkdir, rename/move,
regular-file unlink and empty-directory deletion through sealed
`NativeNamespacePatches`. Extraction requires source/generation binding and an
explicit supported namespace report; absence of ordered-data evidence alone is
insufficient. All namespace replacements, including directory bodies and newly
allocated directory/indirect blocks, remain journaled metadata. Before writes,
an independent original-owner scan excludes every allocated regular-file payload
block from namespace redo, including the entire block containing a partial EOF.
It bounds file maps, allocation-bitmap reads, comparisons and cancellation.

Independent host tests cover 984 modeled namespace interruption cases with cold
recovery across 1/2/4 KiB. All five host/portable checks pass in
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

A separate private recovery entry point now preflights the same mutable storage
capability, checkpoints all final redo blocks with durable readback, publishes
the journal sequence and then inactive start with separate barriers, and clears
only the primary recovery-flag byte last. It admits checksumless journal and
filesystem controls with journal first block one. Before publication it inventories
every journal block header and chooses a sequence absent from the whole journal,
preventing a torn start from selecting an old transaction. A mismatched first
sequence requires either an already absent current sequence or a bounded alternate
scan whose final redo bytes exactly match durable homes. Ambiguous states refuse
before writing. Any error after possible mutation retains its cause and reports
uncertain durability; retry revalidates the complete source.

Nine independent synthetic recovery tests, alongside six preflight tests, cover every modeled write/flush cut,
prefix tears, high-byte rollover, stale historical commits, volatile persistence,
short writes, readback failure, cancellation, phase budgets, inactive closure and
clean idempotent retry. These are storage fault models, not native crash evidence.

Recovery also rejects changes to group zero's raw inode-table pointer, including
the high word for a 64-byte descriptor. Preserving the final journal inode and
allocation map alone cannot make a torn relocation recoverable. A counterexample
with a structurally clean final state exercises this distinction.

The modeled native-cut gate now covers 374 fault cases, 21 distinct persisted
images and 84 native commands across 1/2/4 KiB profiles. It feeds modeled persisted
bytes to independent e2fsprogs recovery and checks cold partmgr retry. Native
sequence 3 or 4 is checked independently against the cut state; partmgr's absent
restart sequence remains 3. `E2FSCK_TIME` fixes timestamps deterministically;
timestamp bytes are compared, not masked. The final qualification passed at
`/data/cache/partmgr-ext-foreign-native-cuts-20261011-v3/qualification.json`.
The receipt binds the completed matrix and its rejection controls. This is
modeled interruption evidence, not kernel, mount, hardware or native crash capture.

Foreign preflight keeps the first unconsumed scan transaction ID separate from
the virtual empty journal's restart ID. The restart ID advances one further,
modulo 2^32, matching the
[pinned Linux recovery fence](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/jbd2/recovery.c#L324).
The independent three-geometry e2fsprogs oracle at
`/data/cache/partmgr-ext-foreign-preflight-oracle-20261011-v3/receipt.json`
observes transaction 1, scan boundary 2 and native empty sequence 3; it preserves
the original dirty images and compares recovered markers and complete payloads.
The private recovery gate now executes partmgr preflight and recovery against
these images and compares the entire resulting image byte-for-byte with the
independent e2fsprogs result at all three geometries. Clean retries perform no
writes. The binding/rejection receipt is
`/data/cache/partmgr-ext-foreign-recovery-qualification-20261011-v1/qualification.json`.
This does not establish kernel-authored dirty-log correctness, native crash
recovery, checksummed foreign publication or a public editor capability.

Wire details follow the [kernel journal format](https://www.kernel.org/doc/html/latest/filesystems/ext4/journal.html), [commit implementation](https://github.com/torvalds/linux/blob/master/fs/jbd2/commit.c), [recovery implementation](https://github.com/torvalds/linux/blob/master/fs/jbd2/recovery.c) and [`journal_tag_bytes()`](https://github.com/torvalds/linux/blob/master/fs/jbd2/journal.c). Without 64-bit destinations, v2 tags occupy ten bytes, v3 tags sixteen bytes, and legacy tags eight bytes. Native data CRCs cover the escaped journal representation; restoration of the native magic occurs after validation.

The staged transaction controller first commits a native redo transaction containing the current superblock with RECOVER set, then commits the requested mutation, checkpoints durable home blocks, empties the native journal and clears RECOVER. Its preflight transaction preserves the original 1024-byte journal header in two 512-byte capsules at offset 128 of unused descriptor/commit padding, with an explicit versioned marker and native CRC coverage. This retained header supports validation of torn journal activation without guessing opaque header fields. The ordinary redo blocks remain native JBD2 records. The bounded recovery bootstrap verifies capsule and immutable geometry binding, preserves the original journal inode and exact allocation map, constructs a borrowed final-redo overlay and completes its ownership audit before any write. It rejects changes to opaque static journal-header bytes. A clean home state with the original inactive journal header leaves unpublished log records untouched. Single-group filesystems cannot depend on a backup superblock for this step.

Portable tests independently assemble transaction records and forward-polynomial CRC fixtures, reject checksum-valid binding/flag/version defects, and verify cancellation/refunds. Journal-only publication tests cut every write, barrier and readback, including torn writes, with immediate and volatile persistence models; committed recovery yields complete data, while uncommitted tails yield no data. A separate checkpoint recovery test exercises all six home/journal/fence write and flush positions across immediate/volatile persistence, failed flushes with and without persistence, and torn/full write failures: 48 variants. Each restart performs the complete preflight again and produces the exact reference image; cancellation and malformed static headers cause zero writes. These tests do not yet establish the complete owned session or activation/publication fault matrix.

The explicit native codec oracle requires a fresh absolute `PARTMGR_EXT_JBD_EVIDENCE` and runs with:

```text
cargo test --all-features --locked --lib native_jbd2_codec_e2fsck_replay_and_payload -- --ignored --nocapture
```

It independently authors ext3 and default ext4 fixtures through mke2fs/debugfs, prepares inactive v2/v3 checksum headers with an independent CRC implementation, performs same-owner inspection/audit, writes the native preflight and payload redo transactions, and checks independent e2fsck replay plus debugfs comparison of all 131089 payload bytes. Block sizes are 1/2/4KiB. Missing native tools/destination and existing destinations fail. The current twelve-case [codec receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v4/receipt.txt) passed in 4.98 seconds and includes native acceptance of the CRC-covered padding capsules. It is a test-only codec checkpoint; owned-session interruption evidence remains required.

The refreshed [native checkpoint receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v11/receipt.txt) passed all twelve cases in 4.89 seconds. Each committed image follows two independent paths: native e2fsck replay, and the staged borrowed-storage recovery implementation followed by e2fsck `-fn`; debugfs dumps compare all payload bytes in both paths. Its [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v11/verification.json) binds 20 archived sources, the executable, 335 artifact hashes and three fatal negative controls. Earlier codec receipts retain their exact historical scope. No public native editor or complete mutation/session acceptance is claimed.

The private controller is additionally tested across all 24 preparation/activation/fence/mutation/checkpoint write and barrier positions: 192 interruption variants with restart, old-or-new values and exact unrelated home bytes. It validates a clean same-owner audit and the proposed final ownership overlay before publication, rejects removal of the dirty fence before checkpoint, and bounds combined preparation/mutation use of the journal ring. Clean inactive journals ignore unpublished or stale hidden records.

The [v14 lifecycle receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v14/receipt.txt) passed twelve native cases in 5.57 seconds; its [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v14/verification.json) covers 21 archived sources, 339 hashes, the fixed executable and its eleven ordinary tests, native tools and three fatal controls. Each owned-recovered fixture also undergoes the actual controller lifecycle before native `e2fsck -fn` and full debugfs payload comparison. Independently authored journal-magic boot prefixes in 2/4KiB models exercise escaped block-zero superblock redo and dirty-fence preservation. This remains private staged lifecycle evidence; owned generation-scoped operations and their native fault gates remain required.

The staged `Session<S: Storage>` now owns its target and uses checked source-domain-18 and generation counters. Its mapped file handles grant positional access only through that owner; foreign, invalidated, hidden-system and out-of-range handles are rejected. Positional replacement preserves native allocation and metadata, invalidates existing handles, and enters recovery-required state on uncertain failure. Recovery uses the same owner and a fresh cancellation token. The transaction byte cap includes the native journal records, stop block, control headers, dirty fence and affected home blocks.

The [v17 session receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v17/receipt.txt) and [verification](/data/cache/partmgr-ext-jbd-codec-native-20261008-v17/verification.json) retain 22 source bindings, 353 artifact hashes, twelve ordinary tests and twelve native models. The owned models change bytes 37..101 by xor 0x57 and independently compare every byte of the resulting 131089-byte payload. Setup/indexing reads are counted separately from 128 repeated/random retained-handle reads: each request makes exactly one mapped payload read; EOF and empty requests make none. The shared indexed-read loop serves immutable/borrowed decoders and the owned session, with no metadata rescan or `Storage`-to-`ReadAt` authority bridge. Reader/audit/tree/builder/copy/classic-editor/extent/journal regressions pass after this extraction. Public exposure, full allocation/namespace operations and the default legacy-journal writer remain outstanding.

The private owned session now reuses a borrowed same-owner allocation/namespace planning context. Classic public methods delegate to that context without changing their external-undo contract. The native dispatcher accepts filesystem operations rather than caller physical offsets, audits the current owner, verifies the complete proposed ownership state, projects exact disjoint patches onto bounded whole-block redo records, and commits through the native JBD lifecycle. Its initial allocation/namespace profile requires 128-byte classic journaled inodes; 256-byte inodes, extent allocation, checksum-aware modern metadata and default legacy journal writing remain explicit outstanding work.

The independent portable fixture completes create, short-read extension across the direct/single-indirect boundary, truncate, mkdir, cross-directory move with exact non-UTF8 names, last-link file delete and empty-directory delete. A separate seven-operation matrix cuts every write and barrier using immediate/volatile storage, failed flushes with/without persistence and torn/full failures. After restarting from durable bytes, the entire home image matches exactly the old or new state; only the journal data area is excluded from that comparison. Nonempty directory deletion, ambiguous native deletion times and stale handles reject without publication; successful operations invalidate handles and checked generations advance. All retained leases refund.

Native deletion times must be explicit and at least the inode count. Smaller nonzero values overlap the native orphan-list inode-number encoding, as documented by [e2fsprogs `ext2fs_set_dtime`](https://github.com/tytso/e2fsprogs/blob/master/lib/ext2fs/ext2fs.h) and checked by [e2fsck pass 1](https://github.com/tytso/e2fsprogs/blob/master/e2fsck/pass1.c). The dispatcher rejects that ambiguity rather than clamping a supplied timestamp. The common planner now applies the same prewrite rejection to the classic public editor; its signatures and external-undo protocol are unchanged. A retained failed native operation fixture independently exposed this issue at `/data/cache/partmgr-ext-jbd-codec-native-20261008-v19/ext3-b1024-v2-operation-5.img`; it is failed evidence, not an acceptance receipt.

The v21 native gate completed in 20.03 seconds. In addition to the twelve codec/session replay models, it retains 42 operation images across six classic-journal models (1/2/4KiB blocks and v2/v3 checksums), with `e2fsck -fn` after every operation. Independent debugfs dumps compare complete created, extended, truncated and moved payloads, including a 131089-byte deferred append returned in 37-byte source reads. Unrelated original payload bytes remain exact at every step; native UID/GID fields are checked independently. Six further classic ext2 controls show explicit zero-mutation rejection below the deletion-time boundary and clean native output at the exact inode-count boundary and supplied timestamp 1234567. This is staged success evidence plus the portable operation fault matrix; independent native operation failure/restart oracles and the remaining modern/default-journal profiles are still required.

The [root audit](/data/cache/partmgr-ext-jbd-codec-native-20261008-v21/root-audit.json) independently checks all 852 artifact hashes, 27 archived source bindings, 273 successful native commands and 96 complete payload models, including every retained operation payload and unrelated stream. It also checks exact native deletion timestamps and all three fatal gate controls. This remains private classic-session evidence at the scope above.

The [v21 receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v21/receipt.txt) and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v21/verification.json) retain 27 exact archived/live sources, 852 artifact hashes, the fixed executable and its fourteen ordinary JBD tests, native tool binaries/command outputs and three fatal missing-destination/missing-tools/existing-destination controls. The classic editor/copy/builder focused suite also passes 25 ordinary tests. Strict all-target/all-feature Clippy and formatting of the owned files pass. Earlier v17/v20 evidence remains historical after the common planning and deletion-time policy changes; v18/v19 failures remain preserved.

The next private modern planner currently implements extent-backed truncation with 128/256-byte inodes and accepted metadata checksums. It releases audited data and extent-tree blocks, preserves external xattr ownership, zeros the initialized retained tail, and updates inode, block-bitmap, group-descriptor and primary-superblock checksums and free counts. A later same-owner allocation helper appends deferred content, initializes newly allocated blocks, converts touched unwritten extents, and authors canonical indexed extent trees through the native maximum depth of five. It preserves sparse holes and untouched unwritten allocation. Modern namespace operations remain gated. The existing native transaction preflight audits the complete projected ownership state before publication. No public editor capability is added by this checkpoint.

An independent raw fixture covers initialized and unwritten extents, exact truncation payload, stale handles and shared-budget refunds. The six default-ext4 native models additionally truncate to 513 bytes and zero, with independent `e2fsck -fn` and complete debugfs dumps after each operation. Independent native interruption oracles, modern namespace operations and legacy journal publication remain required before broader acceptance. Metadata checksum algorithms follow the kernel's [checksum documentation](https://www.kernel.org/doc/html/latest/filesystems/ext4/checksums.html), [inode format](https://www.kernel.org/doc/html/latest/filesystems/ext4/inodes.html), and [group descriptor format](https://www.kernel.org/doc/html/latest/filesystems/ext4/group_descr.html).

The [v22 staged receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v22-draft/receipt.txt) and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v22-draft/verification.json) bind 28 archived/live sources and 962 artifact hashes, including the twelve native truncation images and expected payloads. The fixed executable passes its ordinary journal tests and all three fatal gate controls; strict all-target/all-feature Clippy passes. The directory retains its `-draft` name to distinguish this narrow modern-operation checkpoint from complete modern editor acceptance. V21 remains intact.

A later portable modern truncation matrix additionally cuts every write and barrier for both lengths across immediate/volatile storage, failed flushes with/without persistence, and torn/full failures. Each restart repeats complete preflight and compares every home byte outside the native journal data allocation to the exact old or new image; all shared leases refund. This test passes in 10.01 seconds and was added after the v22 archived binary, so that receipt does not claim it. Real native interruption oracles remain separate outstanding evidence.

The [v24 indexed extension receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v24-draft/receipt.txt) and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v24-draft/verification.json) retain 28 source bindings and 1532 artifact hashes. Six independently fragmented default-ext4 models append 655445 deferred bytes, with native debugfs stat proving indexed extent metadata, complete payload dumps and `e2fsck -fn`. Truncation to 513 and zero preserves each external 600-byte xattr and all twelve remaining independently authored fragment payloads: 18 xattr and 144 unrelated-stream models. Three fatal gate controls and the fixed executable's ordinary journal tests pass. An independent depth-two sparse fixture, append write/barrier/torn restart matrix, and deferred identity/length/short/oversized/cancellation/cap failures also pass; rejected plans perform zero writes. This remains private extension/truncation evidence, with namespace/default-legacy and independent native fault gates outstanding. V22/v23 archives remain historical after subsequent writer changes.

The later legacy-profile checkpoint exercises native no-checksum journals alongside v2/v3, without a feature upgrade. Independently assembled legacy records verify the complete raw descriptor/data/commit binding before escape restoration; recomputed invalid flags, altered capsules and missing seals reject before recovery writes. The complete publication lifecycle now covers 28 write/barrier positions across eight persistence/failure models (224 restarts), including a pre-existing future commit record. Earlier v26 native success evidence remains retained but its ordinary test run failed a stale 24-position assertion; it is not an accepted receipt. The corrected assertion counts the additional commit-header clear and publication writes. Modern namespace operations and independent native operation interruption oracles remain outstanding.

The [v28 receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v28-draft/receipt.txt) and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v28-draft/verification.json) retain 31 exact source bindings, 2240 artifact hashes, the fixed executable's ordinary journal tests and three fatal controls. Eighteen native legacy/v2/v3 models span ext3/ext4 and 1/2/4KiB blocks; each saved header independently preserves its source feature word and checksum type. Legacy reserved checksum bytes remain zero. The gate also retains 63 classic namespace/allocation operations, nine modern indexed extensions, eighteen modern truncations, 216 unrelated full payloads and 27 external-xattr models. This archive precedes modern namespace implementation and remains a private checkpoint.

The next namespace helper currently performs same-directory exact-byte rename in existing checksum-protected linear leaf slots. It preserves object identity, all inode metadata and allocation, rechecks collision and immutable/append flags, and recalculates the leaf checksum with its owning inode and native generation. A separate independent fixture compares the exact changed leaf and untouched inode table, rejects stale handles and cuts every write/barrier across eight restart models. Cross-directory moves, slot growth, HTree mutations and modern create/delete remain explicitly gated while their complete planners are implemented. These gates do not narrow the remaining operation scope.

The [v29 rename receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v29-draft/receipt.txt) and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v29-draft/verification.json) retain 32 exact archived/live sources and 2332 artifact hashes. In addition to v28's profile/allocation models, nine modern native rename models pass `e2fsck -fn`, independent debugfs payload/xattr retrieval, exact independently extracted inode-byte equality and retained source identity. The fixed executable passes 25 ordinary JBD tests; three fatal gate controls, repository formatting and strict all-target/all-feature locked Clippy pass. V28 remains unchanged and historical relative to the new rename helper. This is private same-directory rename evidence, not modern create/delete/move or complete public editor acceptance.

After v29, separate inode projection and namespace test helpers implement inode bitmap allocation/release, low/high group free-inode/used-directory counts, conservative inode-table high-water marks and primary-superblock free counts. Inode-only edits preserve the unrelated block bitmap, including an uninitialized bitmap. Creation copies caller-provided Linux numeric ownership and 128-byte native time fields; a new 256-byte inode extension is explicitly zero-initialized except its source-profile minimum extra-size and checksums. No clock or ACL-inheritance conversion is implicit. Reused native inode generations increment with checked arithmetic. Existing metadata remains exact except the requested size/allocation/link/deletion fields and required checksums.

Extent-backed linear directory growth initializes a complete checksum leaf, rewrites its bounded native extent index and updates sector counts. Moves preserve the owning inode and hardlink identity; directory moves validate destination ancestry, update '..' and adjust both parent link counts. Empty-directory deletion validates dot topology; nonempty directories reject. Last-link deletion releases the complete audited extent allocation and inode; shared external xattrs decrement their native reference count and checksum, while their last owner releases the block. Hardlink unlink preserves allocation. Indexed-directory mutation and non-extent final allocation/deletion still reject explicitly.

The [v30 namespace receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v30-draft/receipt.txt) and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v30-draft/verification.json) retain 35 exact archived/live sources and 5146 artifact hashes. Nine native models execute seven namespace commits each: 131089-byte file creation, mkdir, file move, directory move, last-link file deletion, rmdir and deletion of the original external-xattr owner. Every commit passes `e2fsck -fn`. Native dumps independently compare four complete new payloads per model, all twelve unrelated fragment payloads after every commit (756 comparisons), and six retained external-xattr values per model (54 comparisons). Numeric UID/GID fields are independently checked through debugfs stat. Eighteen cycle/nonempty-directory controls leave all bytes unchanged. The archived executable passes 32 ordinary JBD tests and three fatal gate controls; strict all-target/all-feature Clippy passes. Portable independent fixtures additionally cut every write/barrier across eight persistence/torn-failure models for create, directory growth, mkdir, file/directory moves and final file/directory deletion, comparing the entire home image outside journal allocation with exact old/new references. Independent native every-cut oracles and dedicated shared-xattr/uninitialized-inode controls remain outstanding. V29 and all prior failed receipts remain unchanged.

The v31 private checkpoint is retained at
`/data/cache/partmgr-ext-jbd-codec-native-20261008-v31-draft/verification.json`.
It binds 35 archived sources, the compiled gate executable, and 11,772 artifact
hashes. All v30 success models remain, and the default ext4 1 KiB/v3 journal model
adds 304 allocated-file deletion interruptions: 38 write/barrier positions across
immediate/buffered persistence, both failed-flush outcomes, and full/torn writes.
Own restart recovery compares every home block outside the independently mapped
native journal against the complete old or new image. Each cut also passes native
`e2fsck -fn` and a complete unrelated 131,089-byte `debugfs` payload comparison.
The separate verifier reconstructs every interrupted image and runs independent
`e2fsck -fy`, `e2fsck -fn`, and complete owner/unrelated payload oracles. Native
replay can update superblock recovery bookkeeping, so its namespace/content proof
is distinguished from own recovery's exact home-image comparison.

Interrupted and recovered images are stored as `EXTCUT01` deltas against the
immutable native `ext4-b1024-v3-namespace-0.img`: eight magic bytes, little-endian
base length, 32-byte SHA-256 of the base, then ordered nonoverlapping little-endian
u64 offset/u64 length/changed-byte records. The verifier checks complete bounds,
base identity, recovered image hashes, and native journal allocation independently
using `debugfs stat <8>`. The first verifier attempt misclassified an inactive
inode-zero directory slot displayed by `debugfs ls -l`; its script and partial
logs remain under `failed-verifier-v1`. The corrected verifier requires a positive
inode. All three enabled-gate failure controls and 34 fixed-binary ordinary tests
pass. This is one operation/profile's independent interruption evidence; it does
not establish every modern operation/profile or expose a public native capability.

Two independently assembled fixtures additionally exercise shared external-EA
ownership with file hardlinks. Three sequential unlinks preserve the EA block
until its final owner, decrement its reference count with the native checksum,
and release initialized and unwritten file allocation only after its final name.
The exhaustive three-transition write/barrier/torn restart matrix accepts only
complete old/new home images, reinspects complete ownership after every cut, and
checks all shared memory reservations are refunded.

The [v32 receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v32-draft/receipt.txt)
and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v32-draft/verification.json)
retain 36 source bindings and 11407 artifact hashes, including the earlier 304
interruption models. Its independent HTree source contains 400 exact 255-byte
names and requires a depth-one interior index. Three native rename/create/delete
operations preserve the index flag, all unrelated names and complete payload;
independent e2fsck checks pass. The fixed executable passes 38 ordinary tests and
three fatal gate controls. This remains a private operation checkpoint.

The v33 and v34 gate failures are retained without acceptance receipts. V33's
final external-EA oracle incorrectly demanded that a released block stay free;
the directory rebuild legitimately reused it. The corrected oracle checks its
new directory owner and rejects retention of the old EA encoding. V34 passes
those native EA checks but stops at the previously extent-only orphan-file gate
for an independently authored checksum filesystem without the extent feature.
Neither failed run establishes native indirect-map operation acceptance.

The reader now validates clean orphan files using native extent or classic
indirect mappings. Every mapped block must be fully initialized, with valid
native orphan magic/checksum and no active entries. The complete ownership audit
also walks all classic pointers, including allocation beyond the visible file
length. Independently assembled fixtures cover checksum corruption, holes and
checksum-valid trailing pointers, with reservation refunds. This follows the
[kernel orphan-file format](https://www.kernel.org/doc/html/latest/filesystems/ext4/orphan.html);
no journal replay or orphan processing is implied by accepting a clean file.

The v35 failure retains the completed seven native operations for each 1KiB and
2KiB classic-map checksum source. Its 4KiB source stops at the former rejection
of a zero reserved-GDT count. The validator now accepts the canonical allocated,
empty double-indirect root for that case, while still checking every pointer,
native inode checksum, exact sector count and absence of global metadata aliases.
Independent checksum-valid malformed fixtures reject nonzero root pointers,
incorrect sector counts and metadata aliases. This matches
[e2fsprogs resize-inode authoring](https://github.com/tytso/e2fsprogs/blob/master/lib/ext2fs/res_gdt.c),
which allocates the root before iterating reserved GDT blocks. V35 has no
acceptance receipt; its failed artifacts remain unchanged.

The [v36 receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v36-draft/receipt.txt)
and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v36-draft/verification.json)
bind 39 archived/live sources, a fixed executable and 11831 artifact hashes.
The native gate passes in 140.79 seconds. In addition to the retained 304 native
interruption models and three HTree operations, it checks three shared external-EA
hardlink unlinks and 21 indirect-map operations across 1/2/4KiB filesystems authored
with metadata checksums and without extents or 64-bit descriptors. Each profile
extends across the double-indirect boundary, truncates to 513 bytes, creates a
file and directory, moves the file and deletes both. Native e2fsck checks every
saved operation image; debugfs retrieves complete independently reconstructed
payloads and confirms unchanged indirect inode flags. The separate verifier
replays all interruption models, compares full payloads, retains command outputs,
and checks three fatal gate controls. The fixed executable passes 41 ordinary
JBD tests and nine modern reader tests. The earlier failed v33/v34/v35 archives
remain historical; no public native capability or complete all-operation native
interruption matrix is claimed.

The [v38 receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v38-draft/receipt.txt)
and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v38-draft/verification.json)
retain 40 exact archived/live source bindings and 11869 artifact hashes. The native
gate passes in 168.64 seconds, retaining v36's models and adding two independent
uninitialized-inode-group operations. A default mke2fs filesystem has 64 inodes
per group; 52 debugfs-authored empty files exhaust the first group's free inodes.
Native creation then selects inode 65, materializes the second group's bitmap,
clears INODE_UNINIT, and updates its native checksum and free counter. Creation
and deletion both pass e2fsck; debugfs retrieves all 131089 payload bytes. Both
operations preserve the first group's entire inode table and bitmap. The separate
verifier rechecks the raw group flags, counters, exact bitmap bytes, all original
names and full payload. Both commits reject earlier-generation handles, and all
leases refund. The fixed executable passes 41 ordinary JBD tests and nine modern
reader tests; three fatal controls pass. V37's wrong test assumption about the
session's initial generation is retained as a failed archive, without acceptance.
Public native editing, wider profiles and complete native interruption coverage
remain unfinished.

The private no-checksum, classic-map planning context now accepts checked
256-byte inode records. Existing records retain their full extra 128 bytes;
new records initialize all 256 bytes and set the superblock's minimum extra size.
The public classic editor retains its 128-byte profile. This follows the native
[inode-size and extra-field layout](https://www.kernel.org/doc/html/latest/filesystems/ext4/inodes.html).
Portable coverage exercises seven namespace/allocation commits, exact existing
tails during replacement, indirect extension and truncation, and every modeled
write/barrier cut under eight persistence/torn-write combinations. Independent
native interruption qualification for this additional profile remains required.
The v39 failed native attempt exhausted its declared planning reservation before
any target change; its failure archive retains the exact unchanged-image check.

The [v40 receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v40-draft/receipt.txt)
and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v40-draft/verification.json)
retain 40 source bindings and 12256 artifact hashes. The native gate passes in
217.03 seconds, adding 21 no-checksum, 256-byte inode operations across 1/2/4KiB
filesystems independently authored by mke2fs and debugfs. Every saved operation
image passes e2fsck. The verifier reconstructs complete payloads, checks exact
existing inode tails and fully initialized new tails, replays the retained 304
native interruption models, and checks three fatal controls. The fixed executable
passes 44 ordinary JBD tests in 158.01 seconds and nine modern reader tests.
This qualifies the private additional profile's positive operations and portable
interruption matrix; its independent native interruption matrix remains pending.

The [v41 receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v41-draft/receipt.txt)
and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v41-draft/verification.json)
retain 40 source bindings and 30871 artifact hashes. The native gate passes in
378.87 seconds and adds 912 independently authored legacy 256-byte inode deletion
interruption models: 38 write/barrier positions, eight persistence/torn-write
combinations, and three block sizes. Own recovery matches complete old or new
home blocks outside actual journal data mappings; unrelated payloads remain exact.
The archived verifier separately decodes each classic journal mapping and replays
all 1216 interruption images with e2fsck, checks complete surviving and deleted
file payloads, and retains native outputs and image hashes. Three fatal controls,
44 fixed-executable JBD tests and nine modern reader tests pass. This expands
native deletion coverage; independent native interruption evidence for every
allocation and namespace operation, wider profiles and public admission remain
unfinished.

The [v42 receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v42-draft/receipt.txt)
and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v42-draft/verification.json)
retain 43 source bindings and 49148 artifact hashes. The native gate passes in
410.99 seconds; the independent verifier replays all 1216 interruption models
and checks nine additional private legacy structural reader/audit fixtures:
default ext3, ext4 with CRC16 group descriptors, and ext4 without metadata or
group checksums, each at 1/2/4 KiB. Complete ownership audits, 400 native names,
a non-UTF8 hardlink alias, external xattrs and full payloads pass. Checksum absence
is a separate policy and supplies no integrity proof. Public admission and native
mutation of these additional profiles remain gated. The fixed executable passes
44 JBD tests and ten modern reader tests; three fatal controls pass. The failed
first verifier is retained: it compared debugfs's escaped non-UTF8 display with
raw bytes. The corrected independent oracle also decodes raw directory records.

The subsequent private planner stage distinguishes CRC16 group descriptors from
metadata checksums when authoring allocation counters, inode tables, extent
nodes, directory leaves and HTree indexes. Fields with no active checksum are
preserved. Independent raw fixtures cover extent/direct maps with and without
CRC16 descriptors: truncate, mkdir, payload creation, cross-directory move,
file deletion and directory deletion each produce a complete clean projected
audit, exact surviving payloads and refunded reservations. These projection
tests do not qualify native journal execution or recovery for the new profiles;
public owned admission remains gated pending that separate proof. A private
qualification constructor now routes the candidate profiles through the same
borrowed-storage journal preparation and complete projected ownership preflight.

The [v43 receipt](/data/cache/partmgr-ext-jbd-codec-native-20261008-v43-draft/receipt.txt)
and [verification manifest](/data/cache/partmgr-ext-jbd-codec-native-20261008-v43-draft/verification.json)
retain 43 exact source bindings, the fixed executable and 32537 artifact hashes.
The native gate passes in 342.16 seconds and adds 72 private owned operation
models: default ext3, CRC16-GDT ext4 and checksum-absent ext4 at 1/2/4 KiB,
each with replace, short-read extension, truncate, file/directory creation,
cross-directory move and file/directory deletion. Independent e2fsck and debugfs
checks cover complete payloads, 400 unchanged native names, a non-UTF8 hardlink
alias, preserved inode tails, native CRC16 descriptors and external xattrs.
The archived verifier also replays all 1216 earlier interruption models and
checks three fatal controls. The fixed executable passes 45 JBD tests and ten
modern reader tests. The new profiles' positive operations do not establish their
interruption/restart matrices; those and public admission remain outstanding.
