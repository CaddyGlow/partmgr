# Native ext journal editing work

The owned native JBD2 engine is under implementation. The current transaction codec and borrowed-storage constructor are compiled only in tests; no public editor capability is exposed. The existing classic `ExtEditor` retains its external-undo contract. Remaining implementation includes public native capability, broader inode/profile support, and the complete independent native operation interruption matrix. The private checksum profile now implements bounded linear-directory and HTree create/mkdir/rename/move/delete, directory growth and extent-backed replacement/extension/truncation. Classic indirect-map checksum planners have portable interruption tests and independent 1/2/4KiB native operation evidence. The staged recovery path now completes its final-redo ownership audit before its first write.

The bounded scanner handles legacy, checksum-v2 and checksum-v3 records, ring wrap, escaped data, committed revocations and incomplete transaction tails. The private writer supports native v2/v3 checksums and a separately bound owned legacy profile. Legacy publication preserves the native no-checksum feature bits and uses a SHA256 integrity footer in kernel-ignored commit padding; recovery rejects foreign unsealed legacy transactions. This footer is not a native journal checksum feature or an authentication claim. Publication durably clears the future commit header, writes and verifies descriptor/data plus the commit body, then publishes its twelve-byte header and verifies the complete commit. A torn header cannot expose a body that has not already passed its durable barrier. Both record count and work, including duplicate/revocation comparisons, consume explicit ceilings; retained maps and redo buffers use shared leases. Whole transaction validation precedes any authorized home-block replay.

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
