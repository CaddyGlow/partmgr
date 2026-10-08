# JFS native-journal editing implementation

This is an implementation checkpoint and protocol design, not a completed writable JFS profile. The existing immutable reader/audit/tree remain the public accepted APIs. Owned editor source domain 19 is reserved; no public editor exports exist yet. Native redo, recovery, file operations, allocation updates and their independent evidence remain required work.

The metadata decoder now consumes a private positional `DecodeRead` contract. Immutable opening retains its `Arc<ReadAt>` for deferred files; exclusive inspection borrows `Storage` and never implements `ReadAt` on mutable storage. System-file metadata reads follow validated extents directly, under cancellation/work limits, instead of constructing immutable payload handles. Indexed metadata is retained separately in `Decoded`, with its memory lease. The same complete allocation/reference audit inspects either result. No file-payload prefetch is needed to bootstrap an editor.

`src/fs_jfs_edit.rs` and `src/fs_jfs_edit_journal.rs` are currently staged under `cfg(test)` and exercised through actual borrowed storage and codec calls. Bootstrap tests inspect native inode/directory maps, including independently inserted external directory structures, assert that regular-file allocation is not read, reject dirty or failing sources without writes, and verify budget refunds. Native-page tests author and decode descriptor-after-data records, check native line vectors and transaction backchain addresses, reject torn page header/trailer pairs, and validate every line before invoking callbacks. The history decoder also covers bounded split records and circular traversal. Authoring now stages single-page UID and bounded dense-file COW transactions; the later checkpoint sections describe allocation, EOF and recovery qualification. Circular publication and broader native operations remain unfinished; the later checkpoints qualify bounded fragmented and external regular-file COW and overlapping ROOT redo precedence. These staging limits do not replace the full requested writable scope.

## Pinned native references

Layout facts come from Linux **v6.17**, independently decoded here:

- [Log superblock, page framing, record types, 36-byte descriptors and 4-byte line vectors](https://github.com/torvalds/linux/blob/v6.17/fs/jfs/jfs_logmgr.h).
- [Record packing, native sequence initialization, mount activation, commit flushing and shutdown checkpoints](https://github.com/torvalds/linux/blob/v6.17/fs/jfs/jfs_logmgr.c).
- [Inode/tree/allocation transaction logging and commit ordering](https://github.com/torvalds/linux/blob/v6.17/fs/jfs/jfs_txnmgr.c).
- [IBM JFS logging design and replay/map reconstruction](https://jfs.sourceforge.net/project/pub/jfslog/jfslog.pdf), Steve Best, IBM Linux Technology Center, October 2000.

Native jfsutils **1.1.15** supplies `mkfs.jfs`, `jfs_logdump`, `fsck.jfs --replay_journal_only`, and the allocation/reference checker. Source definitions in its published `jfs_logmgr.h` agree with the 4096-byte pages, 8-byte header/trailer and 36-byte descriptors. The existing historical immutable receipt is not proof of this new journal implementation. A fresh source/tool/binary-bound native receipt is required.

## Publication and recovery design

JFS journals metadata after-images, not ordinary user payload. The writable implementation must allocate new payload blocks and stream/read back their contents before publishing extent/allocation changes; native hardlinks continue to reference one native inode. This permits bounded range replacement without extracting a whole file. Ordinary in-place payload overwrite cannot acquire all-or-nothing semantics merely from the metadata journal.

The owned transaction must start from exclusively borrowed, complete clean inspected metadata and a validated inactive inline native log. Native aggregate identity, serial, UUID activation and circular page sequence must be validated and updated using native structures. Before publication it must check complete space/caps, retained source identities, every metadata home address and resulting allocation/reference semantics. Native REDOPAGE records contain line after-images followed by native line-vector descriptors; the fixed record descriptor follows the data. UPDATEMAP and inode-map reconstruction must follow native persistent/working-map semantics rather than merely replacing bitmap bytes.

All payload prerequisites must be durable before the redo/COMMIT publication barrier. Home metadata must remain untouched until the complete native COMMIT has been read back and flushed. Home writes and native map reconstruction then complete, flush and verify before a native zero-sync checkpoint, inactive LOGREDONE state and clean aggregate publication. A caller-visible interruption leaves sticky uncertainty until explicit native recovery reopens and validates the same bound aggregate. No external private undo format substitutes for the inline journal.

Recovery must discover the native log end and walk records backwards under explicit page/record/byte/work limits, resolve transaction COMMIT/backchain membership, apply newest line coverage once, and honor NOREDO/UPDATEMAP records and generation semantics. It must validate all replay effects and the resulting complete allocation/reference audit before writes, using a private borrowed positional metadata overlay if necessary. That overlay must not expose mutable storage as immutable `ReadAt`. Torn or unsupported histories reject before writes until their native reconciliation rules are implemented and independently verified. Replay and recovery interruptions require tests under independently retaining or discarding unflushed target bytes, with repeated restarts. Checker/replay success is independent evidence for native metadata semantics; whole payload/native names need separate exact byte oracles.

The requested operation set remains range/replace/extend/truncate, create/mkdir, native hardlink, rename/move/unlink and their allocation, topology, metadata and journal invariants. Unsupported ACL/EA/symlink/special-file or growth profiles must remain explicit until implemented. Mounted-device execution, arbitrary external/shared logs and physical power-loss safety are not established by offline tests.

## Native codec checkpoints

`/data/cache/partmgr-jfs-redo-codec-native-run1` is a failed/incomplete diagnostic. Its original test wrongly accepted exit zero and an applied inode line despite stdout reporting `logredo failed (rc=-245)`; that historical receipt is not successful replay evidence. The strengthened gate rejects failure diagnostics from both output streams even when the native process exits zero.

The formatter's initial zero-sync record begins at the first log-data byte. jfsutils 1.1.15 validates its predecessor address before interpreting the syncpoint, so replaying directly through that formatter marker wraps into the last-page trailer and fails its address bound. The native mount path appends a fresh zero-sync marker after the formatter marker. The corrected staged fixture follows that bootstrap. `/data/cache/partmgr-jfs-redo-codec-native-run2/receipt.txt` has SHA-256 `f862b11178e3ec3e2613c7dec6ae236a072415862b1f754e347a620242c58a34`: `jfs_logdump` recognizes REDOPAGE/COMMIT, native replay completes without failure diagnostics, and the exact 128-byte inode after-image (UID777) is present afterwards. Seven compiled source files, the fixed executable and native command outputs are retained with start/end source/tool/binary checks. This is native record/line codec evidence; the fixture authors dirty native structures directly and does not establish our still-unfinished transaction publication/recovery implementation.

The private history decoder now discovers the native circular log end from checked header/trailer sequences and reads bounded backwards records across page boundaries without retaining the full log. Its present supported record families are SYNCPT/COMMIT/REDOPAGE with a zero syncpoint. Other record families, nonzero older syncpoints, overlapping native redo precedence and complete home-write recovery remain required implementation work before public exports.


## Private owned UID lifecycle checkpoint

The staged borrowed `NativeSession` now prepares a complete clean post-image before mutation, publishes native REDOPAGE and durable COMMIT before the 128-byte inode home write, then flushes/readbacks the home image, checkpoints and clears native activation/dirty state. UID changes preserve the native inode and every hardlink. Recovery checks aggregate binding, record membership, native inode/page/line coordinates, all non-UID after-image bytes and the resulting complete allocation audit before writing. A completed matching checkpoint performs no writes; inconsistent LOGREDONE end pointers reject without mutation. Failures after mutation produce sticky uncertainty. This is private `cfg(test)` staging, not a public general JFS editor.

The explicitly enabled `native_owned_uid_publication_home_error_recovery_and_checker` gate passed with jfsutils 1.1.15 in `/data/cache/partmgr-jfs-owned-uid-native-run2`. Its retained `receipt.txt` SHA-256 is `3ac38138f8b321f610714f3c342b99dbf9cfdefea6595d707c7c30c6257ff9a0`; the retained fixed test binary SHA-256 is `6a9a6a9e07421666bcfb098cf68a5355a00f3f30bd050aaf4d298bd76b3fd28c`. Eleven exact compiled source files and tool hashes were checked at both ends of the run. Exact commands, stdin, stdout and stderr remain beside the receipt.

A native-formatted 64 MiB image with independently authored nested/hardlinked allocations exercised normal completion, a partial home write/error and another error during recovery followed by reopening/retry. Independent native replay on both interrupted copies completed without replay failure diagnostics. All three final whole-image hashes agree; native read-only checking reports clean and `jfs_debugfs` confirms UID305419896. Byte comparison proves every byte outside the UID, native state/serial and inline-log fields unchanged, including payload and allocation bytes. Repeated completed recovery writes nothing. This gate uses actual `FileStorage` flushes, but does not establish physical power-loss safety or all volatile persistence cuts. Torn bootstrap states, broader redo families, allocation and namespace/file operations remain required work. This receipt precedes subsequent recovery-validation changes and is historical evidence for its archived sources.


## Bounded recovery and allocation prerequisites

Private recovery now implements matching-sequence, smaller-EOR page reconciliation following jfsutils 1.1.15 `log_read.c:setLogpage`. Strict history decoding continues to reject differing frames. Reconciliation is restricted to the newest page and validates the entire surviving history and complete post-image audit before repair writes. Ordered short writes of PREPARED, COMMIT and checkpoint pages are tested with retained/discarded unflushed bytes. Sequence changes, malformed EOR and torn older pages reject without writes. This follows the native sequential/no-corrupt/no-unordered-write assumptions; it is not arbitrary-sector corruption recovery.

Sequential native activation also validates old→old+1 little-endian serial prefixes across both aggregate superblocks and the log superblock, including a 255→256 carry, plus prefixes of aggregate UUID activation. Incompatible or ambiguous words reject; partial activation alongside a published COMMIT rejects. Uncommitted recovery aborts the UID change and preserves all home inode bytes. COMMIT-through-clean-header barrier cuts and another interrupted recovery are tested under four combinations of retained/discarded volatile bytes, with repeated completed zero-write recovery and full refunds. Torn checkpoint end-pointer publication and broader histories remain unfinished.

The retained five-case native receipt `/data/cache/partmgr-jfs-owned-uid-native-run4/receipt.txt` has SHA-256 `cec477907f27f7728f5d972b3bf635f35ceccaf62eff87e6344ca3cb73000bb2`; its fixed executable has SHA-256 `06629f3711ea62438c69c842f4fd4d729f2b3cf7c5962c774b76da4fc86e1ce8`. Three committed cases reproduce diagnostic-clean independent replay and UID305419896. Two partial-bootstrap cases reopen through our validated uncommitted abort, preserve UID501 and every home/payload/allocation byte, and then pass native read-only checking and exact debugger UID checking. Those two cases do not claim independent native replay of their interrupted bootstrap state. Eleven exact compiled sources/tools/binary have start/end checks; this checkpoint precedes the allocation helper below.

The test-staged `fs_jfs_edit_allocation.rs` prepares native working/persistent allocation-map, group/global counters and buddy-summary after-images from validated system-map runs. Its independently constructed one-block COW fixture redirects a regular inode, frees its old block and allocates another; the borrowed decoder and complete ownership audit accept the resulting metadata overlay. This is preflight and does not publish payload, native allocation records or COMMIT. It grants no mutation authority on its own. Changed pages retain charged before/after images; input sorting, word-buddy probes, summary rebuilding and map traversal are bounded by work/memory/cancellation caps. Public file, allocation and namespace operations remain unfinished.

The private recovery preflight now distinguishes a journal-authorized metadata
index from an ordinary validated index. The former carries no allocation audit,
free-range, directory or deferred payload authority. It validates sorted unique
allocation masks and rejects working/persistent bitmap differences outside those
masks. Native bitmap, free-count and buddy afterimages are regenerated from the
authorized desired bitmap; observed pages must match an ordered prefix of the
canonical new page followed by the canonical old page. Unchanged native pages
and unused allocation-group counters are checked too. Regeneration cannot erase
an unrelated count or buddy discrepancy. Work, retained pages and scratch are
charged independently, with cancellation and refund checks.

The committed COW codec fixture preflight validates COMMIT/backchain membership,
native fileset/inode/page identity, separate root-header and XAD vectors, one
NEW recorded XAD allocation and its matching old FREE record. It overlays the
committed tree change and regenerated map pages, then runs the ordinary strict
decoder and complete ownership audit before returning. It returns no replay or
mutation capability. Ordinary tests cover eight partial native page prefixes,
unauthorized same-word bitmap differences, unrelated buddy damage, malformed
allocation authorization and resource refunds. General owned COW publication,
range operations, namespace allocation and their restart fault matrix remain
unfinished; the public reader profile remains strict.

The retained native refresh is
`/data/cache/partmgr-jfs-owned-uid-native-run11/receipt.txt`, SHA-256
`48d64c392f837d4a5b7278e90a35cacacea6618a9d9b6ffedc4c1913f514a9d7`.
Its fixed test binary is
`2ad17482473298c2819b7d68f25bb51ce9a2708ae133037abc74f7d251034ae4`.
Fourteen compiled source files and tool/binary bytes are guarded at both ends.
Seven retained native cases pass, including the COW preflight followed by
independent diagnostic-clean allocation replay. This is private UID lifecycle
and allocation-codec/preflight evidence, not an owned COW publication claim.
Run 8 remains an unaccepted semantic diagnostic: a single root vector spanning
header and XAD bytes does not perform native allocation replay. The accepted
fixture uses distinct header and XAD vectors.

The private owned COW checkpoint now publishes replacement content for one
existing inline, recorded block through that native journal grammar. Preparation
checks a complete clean ownership audit and every native afterimage before any
write. Publication reads the deferred source in bounded short reads, initializes
the fresh block and its zero tail, flushes and verifies it, then durably publishes
the native commit. Recovery validates the complete committed metadata overlay,
regenerates allocation counts and buddy summaries, and runs the strict decoder
and complete ownership audit before replaying home metadata. Uncommitted
activation is aborted without changing the old inode or its allocation.

The fault model exercises 1,457 publication short-write cuts with four first-
and recovery-restart retain/drop histories, 1,568 committed and prepared recovery
short-write cuts with both persistence outcomes, and every modeled flush barrier.
Target and inline journal share one Storage flush authority. These are modeled
errors and volatile-byte persistence extremes, not physical power-loss evidence.
Rehashed semantic negatives, stale preparation and cancellation reject with zero
writes; completed recovery performs zero writes and retained leases refund.

The source-bound native refresh is
`/data/cache/partmgr-jfs-owned-cow-native-run14/receipt.txt`, SHA-256
`1ac0727e5bcb8dfc6e6090fc85c5d847945212a24ecd6c7fabb384404fc916a6`.
Its retained fixed binary is SHA-256
`b3405ea3c558026c0be072529ecf02e15dc8fa114d7bdb6f2a7fcdcb142a58f8`.
Fourteen compiled sources, native tools and binary are checked at both ends.
Ten cases include owned publication, interrupted native replay without failure
diagnostics, recovery retry, unchanged native metadata and two hardlinked names,
exact replacement bytes and zero tail, native clean checks, and identical final
images. Native debugger extent addresses plus independent physical-byte models
provide the payload oracle; no native whole-tree extraction claim is made.

This remains private staging. General fragmented and external extent-tree publication,
range edits, extension, truncation, allocation and namespace operations, and the
public domain-19 session API remain unfinished. Source identity and length checks
do not establish a byte snapshot: deferred input requires caller-guaranteed
stability. The strict public reader continues to reject dirty profiles.

The subsequent private draft extends the same native root/free grammar to one
contiguous recorded run of 1–16 blocks while preserving file length. It streams
one 4096-byte block at a time, initializes the final tail, and verifies every
fresh block before publishing COMMIT. An independent three-block, 9000-byte
fixture checks allocation of every new block, release of every old block, exact
payload and tail, preserved hardlinks, and unchanged old payload bytes. A source
failure in the second block reports causal mutation uncertainty while the old
namespace remains authoritative and the strict clean audit still passes. This
draft is later than the run-14 receipt; its native and broader persistence
qualification is separate. Fragmented mappings, external trees and file-size
changes remain unsupported by this draft, with further native grammar and
afterimage proof work required.

The contiguous-run draft has a later source-bound native receipt at
`/data/cache/partmgr-jfs-owned-cow-native-run15/receipt.txt`, SHA-256
`3f534b9c44121645a95fe7ff04a462b2532ed78c74fa8c3de44222f87a626fd4`;
its fixed binary is SHA-256
`d9128d09620d4dd28ecfc7307cd45036212bdc45346d72b0588b65b0b18b6dd9`.
In addition to the previous cases, a three-block native source is expanded using
the checked map constructor and independently checked by jfsutils before owned
editing. This is checked fixture setup, not independent allocation-map authoring.
An interrupted native COMMIT is replayed independently; both native and owned
recovery expose the complete 9000-byte independent pattern, exact zero tail,
all old/new allocation bits and the unchanged old payload. Read-only native
checker and debugger observations, artifacts, hashes and exact commands are
retained. Broader multi-block failure matrices remain separate unfinished work.

The next exact source-bound refresh is
`/data/cache/partmgr-jfs-owned-cow-native-run16/receipt.txt`, SHA-256
`017ef3ed5a97aba35ff979c222280f43186889f509a51ca46a5d2e3f91670feb`;
its fixed binary is SHA-256
`f8ebcdebe0623861797a2415ceb40f397a6e6ed5ea77ef97bb1de73bca99ed29`.
It binds the additional ordinary three-block matrix: 878 publication partial
program positions and 16 flush barriers with four first/recovery restart
retain/drop histories. Recovery is interrupted at its first program before
another restart. Every history checks the complete surviving logical payload,
tail, all old/new allocation bits, hardlinks and repeated no-write recovery.
A COMMIT retained after its failed flush can still disappear when recovery's
first program fails before a flush and the second restart discards volatile
bytes; that history correctly retains the old tree. Exhaustive cuts at every
three-block recovery position remain a separate unfinished qualification.

The next grammar expansion must represent all old recorded/unwritten runs and
external xtree pages in native FREE records, and all fresh runs in native root
or external-page redo. Length and allocated-block changes require a separate
native INODE line alongside tree redo, preserving unrelated metadata and the
native hardlink identity. Recovery must overlay every committed inode/tree
afterimage before reconstructing authorized bitmap masks and counts. A tentative
allocation index cannot authorize payload, free ranges or an ownership report.
Range operations additionally need bounded borrowed positional reads of the old
audited map during fresh-block emission; mutable Storage must never be presented
as immutable ReadAt or FileRead. Publication capacity, all fresh extents and
old-history frees must be preflighted before the first payload write, including
native circular log-page capacity and sequence rules. No fallback to an external
undo protocol or whole-file prefetch is permitted.

The staged dense replacement now also emits a native INODE line when EOF or
allocated-block count changes. It preserves the native inode and all hardlinks,
streams one fresh 4096-byte block at a time, and accepts one inline recorded run
of 1–16 blocks with a nonzero EOF. Committed recovery validates the INODE line's
immutable fields, ROOT and FREE relationships, then overlays all afterimages
before canonical allocation reconstruction and the strict complete ownership
audit. The native redo log supplies no old EOF preimage: interrupted home writes
are checked against a bounded legal old EOF interval and the ordered afterimage
prefix; this does not prove the exact overwritten old EOF bytes. Empty files,
fragmented/external trees, range recipes and namespace editing remain unfinished.

The diagnostic-clean dense native checkpoint is
`/data/cache/partmgr-jfs-owned-dense-native-run19/receipt.txt`, SHA-256
`0bb624d7b3b949cea4b48e14f27b4673f2d3544697e2be4dc534fd1160a799a7`;
its fixed binary is SHA-256
`d89f8bfb4f361d75fc458d55c1c4e0426d96cbb938d9825d8795538749bc9385`.
It binds fourteen compiled source files and revalidates source, tool and binary
hashes at completion. In addition to prior lifecycle observations it compares
owned and independent native committed recovery for 7→4200-byte and
7→65536-byte growth and 9000→7-byte shrinkage. Both paths pass read-only native
checks, exact native hexadecimal EOF/block-count fields, complete logical payload
models, zero tails, two hardlinks and unchanged old physical data. Run18 failed a
decimal debugger-format assertion and remains an unaccepted diagnostic. Run19
became historical when the subsequent resize interruption test extension landed;
it does not bind that later test source or establish exhaustive resize cuts.

The refreshed current dense checkpoint is
`/data/cache/partmgr-jfs-owned-dense-native-run20/receipt.txt`, SHA-256
`16ff2c0e849897e15054c3c45b5fc533f803025740021449616ec42727f34a36`;
fixed binary SHA-256
`1820390c78c4ac05b6849884fa1f393e29785253f86b7fd7a7e60585f9b8e556`.
The same fourteen-source native gate passes and now binds the portable resize
matrix. Shrinkage from 9000 to 7 bytes covers 762 program positions and fourteen
flush barriers; shrinkage to 4200 covers 820 positions and fifteen barriers.
Every position runs all four retain/drop combinations across initial and
interrupted-recovery restarts, validates full surviving content and native EOF,
block count, hardlinks, old physical bytes, and repeated completed zero-write
recovery. Six malformed committed histories per resize reject impossible EOF,
wrong block count, unrelated metadata changes, malformed INODE vector length,
wrong transaction backchain and unauthorized bitmap differences before any write
or flush; both visible and durable byte models remain unchanged. The native log
has no per-record checksum to recompute for these structurally framed semantic
negatives. Resize recovery is interrupted at its first program; exhaustive cuts
at every later resize recovery position remain unfinished qualification. These
model persistence extremes do not establish physical power-loss behavior.

The staged range-emission implementation retains a bounded old-map recipe in
the prepared exclusive plan, rather than exposing mutable backing storage through
ReadAt or FileRead. A replacement source is an independent deferred FileRead with
captured identity and length; unaffected old logical spans are read positionally
from the audited old map only while the editor owns Storage. A single fresh-block
buffer combines old recorded bytes, explicit zeros and replacement bytes. Fresh
allocation must be disjoint from every old owned extent, and old metadata/map
facts must be revalidated before emission. An interrupted source read after any
fresh-block write still latches uncertainty even though the old namespace remains
authoritative before COMMIT. Native INODE and tree afterimages, every old FREE
extent, capacity, EOF arithmetic and all fresh allocations must be prepared before
any mutation. This remains a private test-staged path, not a public range API.


The staged range path preserves old logical spans and materializes the EOF gap
while emitting fresh disjoint blocks. Native checkpoint
`/data/cache/partmgr-jfs-owned-range-native-run21/receipt.txt` has SHA-256
`b5363b5289d501d7879300cd512b31d95cae28a41940991b27d9e368ffabca75`;
fixed binary SHA-256
`5948f0fd4e2160306f50c6c3f25110a0431799a32ff341fac19fcc7665f9bc71`.
Its fourteen-source closure passes start/end checks. Independent native and owned
committed recovery both validate all 9090 logical bytes for replacement at 4090,
and all 17000 bytes for replacement at 12000 with a zero gap, from a 9000-byte
three-block baseline. Exact native EOF, allocation counts, hardlinks, tail zeros,
retained old physical data and read-only checks pass. The replacement is 5000 bytes
in both cases and has an independent positional pattern. Run21 became historical
when the range-specific fault-matrix test extension landed. The full host run20
is failed due an APFS snapshot-work interruption, not full host acceptance; its JFS
matrices passed. Fragmented old maps, empty truncation and namespace operations
remain required unfinished work.

The exact current range refresh is
`/data/cache/partmgr-jfs-owned-range-native-run22/receipt.txt`, SHA-256
`dd8d8b7f6647c8547ef21f180753d20e48396d9b7b7e783dca2f3bdd0ad49448`;
fixed binary SHA-256
`6c38489f01aa4861dc8c8f630166fd46ed37a1506b1485c5e47b42d4d2ba9f43`.
It binds the additional range matrix: 878 program positions and sixteen barriers
at offset 4090; 994 positions and eighteen barriers at offset 12000. Every position
runs four initial/recovery retain/drop histories with another interruption at the
first recovery program, sticky denial of further edits, whole-content and
allocation checks, hardlinks, zero tails, retained old physical bytes, repeated
no-write recovery and lease refunds. Fast preflight tests reject EOF overflow,
output beyond sixteen blocks, empty range sources, cancellation and zero memory
budget before any write or flush. A deferred replacement failure after its first
fresh block preserves the causal source error, latches uncertainty, prevents
further mutation and recovers the unchanged old namespace. All-position cuts at
later range recovery programs, empty truncation and fragmented histories remain
unfinished qualification. The public mutation API remains closed.

Empty truncation is now staged through the same owned session: it emits a native
INODE line with EOF and block count zero, ROOT nextindex 2 with the removed XAD
cleared, and the old FREE record. It emits no fresh payload block and preserves
old physical bytes. Recovery validates the old/new nextindex transition as part
of the ordered inode prefix, reconstructs only the old free authorization and
requires the strict complete post-audit before replay. The removed unused XAD
must be zero in this authored profile. The portable matrix covers 704 program
positions and thirteen barriers across four two-restart persistence histories,
including interrupted first recovery, exact old-or-empty tree, native fields,
hardlinks, allocation, unchanged data and repeated no-write recovery. Five
malformed committed histories reject inconsistent EOF, block count, nextindex,
unused XAD and FREE extent before any write or flush.

The exact source-bound refresh is
`/data/cache/partmgr-jfs-owned-empty-native-run24/receipt.txt`, SHA-256
`03e2b9f674328dd8bda1ae07298092997a170f976f9efe16ee8f9a5e6045676b`;
fixed binary SHA-256
`926354ad4d431d12bdb5379bc4ed953ee8b6deaa974434ac75362b334e8ea950`.
It preserves the fourteen compiled source files and passes start/end source,
tool and binary checks. Both owned and independent native committed recovery
produce exact zero EOF/block count and empty tree, preserve two hardlinks and
old physical data, and pass diagnostic-clean replay, native inode inspection
and read-only checks. This adds empty truncation to the bounded single-inline-run
staging; fragmented/external old trees, general native circular publication and
namespace operations remain required unfinished work. The native journal still
supplies no exact old EOF preimage, and exhaustive interruptions at later
recovery positions remain separate qualification.

The next fragmented-inline grammar must use native FREEXADLIST for old data, not
infer logical positions from a sorted physical PXD list. Each retained native XAD
supplies logical offset, physical count and recorded/unwritten flags; recovery
must validate logical ordering, physical disjointness and the exact removed root
slots before constructing before/after inode candidates. Native allocated-block
count is the physical sum, while the bounded old EOF interval comes from the last
logical run. Internal holes and unwritten runs produce zeros in borrowed fresh
emission. A one-run new root may leave old unused slots physically present, but
recovery must neither treat those slots as ownership nor erase the only history
needed to reconstruct an interrupted old root. External xtree pages require
separate explicitly known metadata FREE records and remain a later grammar.
This design is implemented in the following private fragmented-inline checkpoint.

Run26 accepts one to sixteen inline recorded/unwritten runs, with at most sixteen
physical blocks and a last logical end of sixteen blocks. Internal holes are
supported; trailing holes and external xtree pages remain outside this profile.
FREEXADLIST retains the exact old native XADs. Borrowed range emission reads only
intersecting recorded spans and supplies zeros for holes and unwritten spans.
Replacement, range replacement and empty truncation preserve the native inode
and both hardlinks. The independently constructed source has recorded logical
block 0, unwritten block 2, and recorded blocks 4–5, with four allocated blocks
and EOF 20603. Its native bitmap afterimages use the checked allocation helper;
the layout and payload fixture are authored separately and checked read-only
before mutation.

The portable matrix covers every publication program and barrier position for
the three operations under four volatile persistence combinations, then a
recovery interruption and repeated restart. Seven malformed native XAD histories
reject before any target writes or flushes. The enabled native gate additionally
checks owned and independent native replay, complete payloads, zero tails, old
physical bytes, allocation counts, hardlinks and diagnostic-clean native checks.
Its exact fourteen-source receipt is
`/data/cache/partmgr-jfs-owned-fragmented-native-run26/receipt.txt`, SHA-256
`ace8b1009438bc09ca93f9403c7a31d0a86fb30bffdd2b0f23311a12688c13da`;
the retained test binary hash is
`bb7df649656632d02eb5ef1359f688a46522dcb43f6862e2beb3a0e7d1d12e08`.
Run25 remains historical because its receipt mislabeled the old block count;
run26 records all four physical blocks and the exact three runs. This checkpoint
does not qualify external trees, general circular publication or namespace edits.

Run26's full locked all-feature host gate completed with 75 suites, 550 passed,
57 ignored and zero failures. The log
`/data/cache/partmgr-jfs-owned-fragmented-run26-host.log` has SHA-256
`9abc85108b3fa93d4a49d3110d7454e61a5c43da700340e967783f3e6560076d`.
The fourteen-source JFS closure remained unchanged through qualification.
Formatting and strict locked all-target/all-feature Clippy passed after shared
HFS and Ext draft fixes; their earlier failed checks remain historical diagnostics.
Other agents changed shared-checkout sources, so this is not a frozen whole-tree
snapshot claim.

Run27 separately proved native overlapping ROOT redo precedence from an intact
old home inode: an earlier ordinary ROOT record retains the canonical old root,
and a later ordinary ROOT record supplies the new XAD. Independent jfsutils
replay selects the later root, allocates and clears its NEW flag, frees the old
block and passes strict complete ownership and native read-only checks. This is
a codec oracle, not external-tree publication acceptance.

Run28 additionally reconstructs canonical old allocation-map pages separately
from their observed possibly partial bytes. Recovery requires strict ordinary
decode and complete ownership audits of both old and new projected trees before
replay writes. Map page retention and both overlays have explicit shared memory
reservations. The old EOF remains a legal candidate established by the positional
prefix proof; the native records do not supply an exact old EOF preimage.
The fragmented exhaustive cut matrix passed with this additional audit.
Its guarded native receipt is
`/data/cache/partmgr-jfs-old-new-audit-native-run28/receipt.txt`, SHA-256
`b2b08c84c53ef1d1c6b459356b1d14cf8bb673c2017fe7633242e6cab8cb04ab`;
the retained binary hash is
`de84c38e5b847ac4c430d58cb4bef335c0838bf932929473bcf2c106963bd577`.

The run24 full host gate completed successfully with 74 suites, 534 passed,
54 ignored and zero failures. Its log is
`/data/cache/partmgr-jfs-owned-empty-run24-host.log`, SHA-256
`b2af44100c71895603ef6bec7130db6615150e0b03eebfd1322e4a5a43140d7f`.
The JFS engine/test closure remained unchanged through the native and full host
gates; other agents' shared-checkout work means this is not an immutable
whole-repository source snapshot claim. Required formatting and strict locked
all-target/all-feature Clippy checks also passed. The failed run20 APFS gate is
retained separately; it is not used as full host acceptance.


## External regular-file COW checkpoint

The private profile now accepts up to 32 logical/data blocks and up to eight
external extent-tree pages, with at most 32 total old allocated blocks. Output
remains one contiguous fresh run of at most 32 blocks. Internal holes and
unwritten extents become initialized zeros. Trailing-hole sources, empty source
inodes, circular publication, namespace changes and public mutation remain
unfinished.

External source transactions carry the actual old native ROOT redo before the
new inode/ROOT records, a native FREE XAD list for data, and a native FREE PXD
list for validated external metadata pages. Recovery checks exact record roles,
backchains and disjoint allocations, then strictly decodes and completely audits
both canonical before and after projections before replay. The observed old EOF
is a legal prefix-compatible candidate, not an exact journaled preimage.
Deferred publication revalidates the inode, every decoded data run and metadata
page before payload writes; a valid changed unwritten flag is rejected as stale
without target or journal mutation.

An independent fixture contains 17 recorded data runs, one external leaf and two
hardlinks. Replace, range replacement and empty output pass every publication
program/barrier interruption across four volatile persistence combinations.
Committed recovery separately passes every one of its 414 program and eight
barrier interruptions, with interrupted recovery followed by another restart.
Rehashed malformed OLD_ROOT, metadata FREE and transaction-chain cases reject
with zero program or flush attempts. These are modeled storage/flush guarantees,
not physical power-loss or mounted-JFS evidence. Pristine payload writes use a
4096-byte buffer; old payload is borrowed positionally rather than prefetched.

The source-bound native run31 completed successfully in 39.56 seconds. Its
receipt is `/data/cache/partmgr-jfs-external-owned-native-run31/receipt.txt`,
SHA-256 `8a962ea8c7a28b8babe22f3bb4a53aef9b785979ac795ec29e3088ca95233289`.
The retained binary SHA-256 is
`ca0e30d62f675c73f277734bc7f3a9db51a1397b29da8e5e797b50a79dda2be1`.
Fourteen compiled source files, native tools and the fixed binary were checked
at start and end. Native source checking and interrupted replay diagnostics were
clean; complete logical payloads, both hardlinks, metadata/data allocation,
initialized tails and unchanged old payload/leaf bytes were compared. Run30
remains historical evidence from its earlier compiled source checkpoint.

The required run31 full host gate completed with 75 suites, 570 passed,
61 ignored and zero failures. Its retained log is
`/data/cache/partmgr-jfs-external-run31-host.log`, SHA-256
`80ad03e33ae9a725bbb8cec3cc5bae8b7ee0ec7e2fd08e657b8789337ba3cbb4`.
Formatting and strict locked all-target/all-feature Clippy also passed. All
fourteen compiled JFS source archives still matched the checkout after the
full gate. Other agents' intervening files are not part of a frozen whole-tree
claim. Public mutation remains closed; this qualifies the private bounded
external-file COW profile, not the full writable JFS family.


## Pristine native checkpoint rollover

The next private bootstrap moves a complete clean native zero-address SYNC
checkpoint into the pristine physical successor, including wrap from the last
log page into page two. It requires a unique durable old SYNC, inactive/redone
log, strict complete source ownership audit, a nonwrapping sequence increment,
the expected native predecessor sequence and a hidden canonical SYNC descriptor
in the unused successor. Occupied-page recycling and records spanning multiple
authored pages remain unfinished.

Native mkfs.jfs leaves bytes beyond an empty page EOR unspecified. Rollover
preserves those unreachable bytes and writes only two eight-byte framing patches
then the four-byte log-end word, with a checked flush after each publication
phase. Recovery authorizes only exact ordered framing/log-end prefixes against
the old durable SYNC; it does not normalize arbitrary torn pages. The public
strict reader and ordinary scanner are unchanged. Ring/header SHA-256 checks,
aggregate UUID binding, 64-KiB retained/scratch charge, page/work caps and causal
metadata reads precede writes. Recovery and publication use borrowed Storage,
without a mutable ReadAt implementation or payload extraction.

Portable evidence covers every publication/recovery program and barrier,
retained/dropped first and second restart states, repeated interrupted recovery,
sticky session uncertainty, physical wrap, stale rings, malformed native
prefixes, caps, cancellation and causal read failure with complete refunds.
Independent native run34 additionally checks three successive checkpoints,
authors an explicit clean last-page anchor fixture, wraps into page two, runs an
interrupted UID transaction through native jfsutils and owned cold recovery,
then publishes and independently checks a 9000-byte COW payload with two
hardlinks, released old allocation and initialized tail.

The final native receipt is
`/data/cache/partmgr-jfs-pristine-rollover-native-run34/receipt.txt`, SHA-256
`c2e4917f44adb861660b1f69ccc91e69eb6eb74cecc6d28ccd76204151205710`;
retained binary SHA-256
`517ddf640bb10caec8ce2403f3228ec57fd65ce20bfd23e09632f45b3f704d43`.
Fifteen compiled sources, tools and binary match at start and end. Native replay
and read-only checks are diagnostic-clean. Run32 remains a failed profile
experiment: its whole-empty-page-zero assumption rejected native formatter
bytes. Run33 is an earlier successful source-bound checkpoint. These proofs
cover declared storage/flush models and actual file syncs, not hardware power
loss, mounted use or the complete writable family.

Run34 required full host gate completed with 75 suites, 584 passed, 67 ignored
and zero failures. The log is
`/data/cache/partmgr-jfs-pristine-rollover-run34-host.log`, SHA-256
`504d85fc0f35097868d4543138f7cc5bccac0ccab1ceec08d24909f2941c2a50`.
Formatting and strict locked all-target/all-feature Clippy passed after unrelated
Ext staged-code fixes. All fifteen native compiled source archives still matched
the checkout after the full gate. Subsequent combined operation preparation is
a separate checkpoint; this does not freeze other agents' repository files.


## Combined checkpoint and COW preparation

An explicit private session operation now prepares native checkpoint rotation and
regular-file COW as one bounded plan. COW preparation consumes the existing
positional DecodeRead contract through a checked metadata-only overlay. It
validates the complete projected tree, allocation maps, source identity/length,
space and caps before any rotation or payload program. Publication revalidates
the actual inode/extent graph, map preimages and full ring digest, rotates the
checkpoint, then emits the existing native INODE/ROOT/FREE transaction. A later
failure remains sticky uncertainty even when COW has not become committed.
Recovery validates native COW first; only a pre-mutation structural/profile
rejection may enter the separately strict clean pristine-bootstrap proof. I/O,
budget, cancellation or uncertain replay errors never trigger that fallback.

Portable qualification covers all 881 publication programs and 18 barriers,
four first/second restart persistence combinations, interrupted recovery and
zero-write repeated completion. Recovery itself covers every bootstrap program
and barrier and all 414 programs/eight barriers after COMMIT, from both retained
and dropped initial HOME bytes. Deferred second-block I/O failure preserves its
cause and recovers the old seven-byte hardlinked file; stale rings, over-cap
requests, cancellation and insufficient memory reject before writes and refund
all reservations. The regular-file 32-block profile and source restrictions
remain unchanged. Default operations do not implicitly select rotation.

Native run35 is a successful earlier fifteen-source checkpoint with additional
combined preflight-zero-write, COMMIT/torn-HOME, owned/native replay and complete
9000-byte payload, tail, allocation and hardlink checks. Its receipt is
`/data/cache/partmgr-jfs-combined-rotation-native-run35/receipt.txt`, SHA-256
`9d30b29eba6aacdc53ef0d941d73663c6008288fead40690a9d4ddb27134da6e`;
retained binary SHA-256
`f6dd10c47c3c362118b7bd645fe992785c425085fece3404b7e7190cd5d7254c`.
The final source-bound refresh run36 passes in 37.65 seconds. Its receipt is
`/data/cache/partmgr-jfs-combined-rotation-native-run36/receipt.txt`, SHA-256
`f0111ff48386f7e39b651301d8f04c3cb2b7ff935bf03c89919fd0f963029b95`;
retained binary SHA-256
`3c89232edc3fe2dfd3b61ae6482bae566c3ba5b27c5348d0bb051f946999bad0`.
All fifteen compiled source, tool and fixed-binary guards match at start/end;
native replay/checker diagnostics are clean. Split-record authoring, occupied
page recycling and broader namespace/allocation operations remain required work.

The final run36 required full host gate completed with 75 suites, 598 passed,
70 ignored and zero failures. Its retained log is
`/data/cache/partmgr-jfs-combined-rotation-run36-host.log`, SHA-256
`bded4b0898fc4959e6d6f2d7b0697ff5cbe9735f3967947574a44cb9b24d4369`.
Formatting and strict locked all-target/all-feature Clippy passed; all fifteen
native compiled source archives still matched the checkout after the full gate.
The isolated occupied-page prototype was not part of these live sources and is
not accepted by this checkpoint. Other agents' files are outside a frozen
whole-repository claim.


## Checkpointed occupied-page reuse (private draft)

The additive `prepare_recycling` and `prepare_recycling_cow` paths permit an
older physical successor behind a proven latest durable zero-address native
SYNC. The unchanged pristine path rejects occupied successors. Eligibility
requires a clean inactive/redone single-aggregate volume, complete strict
ownership audit, exact native ring sequence position, canonical first SYNC,
and bounded whole-ring/header digest revalidation before the first write.
The latest anchor is never overwritten. Sequence-number wrap and nonzero SYNC
stop addresses remain unsupported.

[Linux v6.17 lmNextPage](https://raw.githubusercontent.com/torvalds/linux/v6.17/fs/jfs/jfs_logmgr.c)
defines physical wrap to page two and the next page sequence. The independent
jfsutils 1.1.15 `libfs/logredo.c` LOG_SYNCPT handler stops replay at the SYNC
record itself when its address is zero. This retirement boundary, combined
with complete clean home-state validation, is the authority for discarding
older reachable journal records. Unreachable body bytes are preserved.

Cold recovery accepts only the exact ordered positional framing/log-end
prefixes. A surviving old framing half supplies its legal old EOR. When both
halves are new, a compatible retired framing is sufficient for the older
anchor proof; this does not recover or assert an exact historical old EOR.
All payload/allocation authorities still require ordinary checked decoding
and complete ownership audit before mutation.

The isolated native run37 at
`/data/cache/partmgr-jfs-recycling-native-run37/receipt.txt` passed 511 rotations
of a 256-page native log with completed UID histories every 32 iterations.
An interrupted COW after those rotations passed independent diagnostic-clean
jfsutils replay, exact 9,000-byte payload and zero tail, and both hardlinks.
Its fifteen compiled sources are archived from the isolated workspace; it is
not the final live source receipt. Portable occupied-target tests passed all
881 publication programs/18 barriers and 414 committed recovery programs/eight
barriers across four volatile persistence combinations and repeated restart.
Final live qualification is pending. These are functional durability models
and actual FileStorage flush observations, without mounted/hardware power-loss
claims. Split-record authoring and broader namespace operations remain unfinished.


The final live native run38 receipt is
`/data/cache/partmgr-jfs-recycling-native-run38/receipt.txt`, SHA-256
`d16fa1f9cc303cd9e50d1bffe4707a86df8fa6a65d3521c552dae601ebf3ec15`.
Its fixed retained test binary SHA-256 is
`8db470896fbc71926bfb30cbb883399d328e1d5891cadd7685f74f0f3c951c5a`.
The gate passed in 77.12 seconds, archived all fifteen compiled sources, and
verified baked/live source equality and source/tool/binary hashes at start and
end. The 256-page native ring executed 511 checkpoint rotations with completed
UID histories every 32 iterations before interrupted COW and independent
native replay. The final independent layout test additionally checks every
physical wrap, sequence, EOR, preserved ignored body and exact log-end against
a separately calculated sixty-step ring model. Active/foreign/nonzero-SYNC,
wrong sequence/type/geometry and stale-ring negatives attempt zero writes.
Formatting and strict all-target/all-feature Clippy passed; final full host
qualification is still running at this documentation checkpoint.


Final run38 required host gates completed: formatting and strict all-target,
all-feature locked Clippy passed, and the all-feature locked full host suite
passed 613 tests across 75 suites with 72 explicitly ignored native/large
qualification gates and zero failures (library 144 passed, 28 ignored).
The retained full log is
`/data/cache/partmgr-jfs-recycling-run38-host.log`, SHA-256
`4a14eaa672f0f9a19bd6449246666d17afa721e5e2cff4e6f0f4b7e9afc64516`.
All fifteen native compiled source-closure files still matched their archives
after the full gate. The earlier pending-qualification paragraphs describe
historical checkpoints; run38 is the final bounded occupied-page-reuse
checkpoint. This does not complete the broader writable JFS family or qualify
public mutation, external namespace trees, split-record publication, or native
inode-allocation namespace operations.
