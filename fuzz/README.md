# Independent partmgr fuzzing

The APFS target includes independently assembled two-volume and retained-
checkpoint seeds, plus a rehashed unsupported unselected-volume seed. The input
ceiling remains 2 MiB; the explicit shared memory ceiling is now 256 MiB to
retain bounded metadata across all audited volumes/checkpoints. Positive smoke
requires both advertised volume selections to reach complete clean accounting
of 57 allocated blocks and full reservation refunds. Multi-volume seeds declare
a sparse 536,875,008-byte logical container while retaining only a 2 MiB prefix;
reads beyond that prefix return declared zeros. Only the exact 4 KiB/131,073-block
fuzz profile permits this extension, and read/audit block caps are 131,073.
These later seeds and
audit changes are outside the sixteen-target receipt below.

The fresh sixteen-target campaign passed 1,002 instrumented iterations per
target with zero crashes/timeouts at
`/data/cache/partmgr-filesystem-fuzz-campaign-1p76ih84/summary.json`.
Root's adjacent `source-audit.json` verifies all 190 captured source hashes,
start/end equality, seeds and native summaries. This isolated snapshot includes
APFS, the ext extent seed and owned JFFS2 creation below. Subsequent engine
changes require new evidence; this remains bounded smoke, not qualification.

The `jffs2` target additionally opens a separately owned NOR edit session in
each byte order, plans a bounded new file with explicit native metadata, commits
through seven-byte short writes into a disjoint 32 KiB external journal, rejects
the previous parent identity, and checks exact payload bytes through a fresh
immutable audited tree after releasing the editor. The mutable backend never
implements `ReadAt`. Every rejected or completed case must refund all leases.
A positive smoke requires this path in both byte orders. This modeled flush
backend provides functional fuzz coverage; persistence cuts remain native-gate
work, and the earlier instrumented receipt excludes these edits.

The `ext` target also includes an independent 64 KiB extent fixture with recorded
data, a logical hole and poisoned physical blocks marked unwritten. Its positive
smoke requires complete clean allocation accounting and exact logical zeros for
both hole and unwritten ranges, with all resource leases refunded. The nineteen
fuzz-library smoke tests and all-target locked Clippy pass for this addition.
The earlier instrumented campaign below does not include this extent seed.

The ext corpus additionally includes independent modern metadata-checksummed
fixtures from `tests/fixtures/fs_ext_modern.rs`: clean extent and direct-map
variants plus four corruption seeds covering shared EA reference counts,
EA/data aliasing, inode CRC and reserved GDT fields. The harness has a4MiB
shared pool and checks refunds after every input; scan/audit/tree ceilings
remain128 blocks,64 inodes,65536 work,32 inventory objects and64 names/maps.
Required smoke verifies public clean audits, exact1700-byte lazy payloads after
volume drop, and cancellation at EOF. These additions require a fresh source-
bound mutation campaign; older campaign receipts exclude them.

Expanded ext/JFFS2 checkpoint:
`/data/cache/partmgr-compressed-modern-fuzz-campaign-xjjwwhss-bfd/summary.json`
passes1001 iterations per target with zero crashes/timeouts and unchanged
sources. Its root audit verifies209 source bindings, seeds and log summaries
against the retained immutable snapshot. Other targets and subsequent changes
are excluded. The initial attempt failed before mutations due to missing bfd.h;
the successful native build used binutils-unwrapped.dev, libunwind and pkg-config
with pinned Rust1.99.0. `scripts/fuzz-campaign.py --target ext --target jffs2`
selects these targets; omit the option to run every configured target.

The `jfs` target covers the bounded Linux JFS reader, complete audit and common
tree using a 2 MiB input ceiling and 32 MiB shared resource pool. Independent
clean/log/mirror/geometry/truncation seeds exercise sparse and unwritten data,
indexed directories, extent visits, retained cancellation and resource refunds.
The positive smoke requires clean audit and an accessible data stream.

The 15-target campaign, including JFS, passed 1,002 iterations per target with
zero crashes/timeouts at
`/data/cache/partmgr-jfs-fuzz-campaign-n8499f4x/summary.json`. The adjacent
`source-audit.json` verifies all 174 captured sources, start/end equality, seed
hashes and native log summaries. It is bounded smoke for that snapshot; owned
JFFS2 edit fuzzing and subsequent ext4/APFS additions are outside this receipt.

Owned targets: partitions, guid, layouts, payload, fat, ext, exfat, ntfs, undo. The layouts target covers transactional edits, owned GPT/MBR decoding, bounded EBR traversal, explicit GPT recovery selection, and write-plan validation; payload covers recovery-record integrity. The fat target exercises geometry, allocation audits, namespace traversal and positional reads with independent packed FAT12 seeds. It also opens a separately owned in-memory FAT edit session with a disjoint external undo store, derives bounded existing-file replacements from validated maps, verifies only the reviewed physical patches changed, rejects old-generation handles and asserts reservation refunds. Limits are512clusters,32objects,64affectedbytes,32undo patches and a2MiB pool; the backend input and8KiB journal memory are separate harness-owned allocations. A required smoke reaches successful commit and generation invalidation. Actual disk failure-cut evidence belongs to the native editor gate. The ext target exercises classic ext2 superblocks, directories, allocation/reference audits, tree inventory and random reads with independently assembled fixtures. The exfat target covers both boot regions, bitmap/upcase validation, entry sets, chains, nested directories and ValidDataLength zero tails through a deterministic zero-padded logical source; its retained independent native-accepted prefix seed has a provenance manifest in fuzz/fixtures. The exfat target additionally exercises complete allocation/reference audit under ceilings of 4,096 clusters, 32 objects, 256 directory slots, 16,384 work units and 32 findings, sharing a 2MiB memory pool. A dedicated smoke requires the native-accepted prefix to reach a complete clean audit.

The ntfs target exercises strict NTFS3.1 boot/MFT bootstrap, FILE update-sequence-array validation, bounded record/attribute metadata, resident/nonresident unnamed files, native UTF-16 names, allocation runs, random/boundary/EOF reads, stale identities and cancellation. Its deterministic 64KiB seed is independently assembled from specification fields; it is not generated by a production writer. The archived constructor and provenance manifest are in `fixtures/ntfs-generator.*`. Dedicated smoke asserts exact resident bytes plus data/hole/data/uninitialized-tail contents. Dirty volume, torn FILE and malformed runlist seeds exercise expected rejection. Each case allows 32 attributes, 64 runs, 8 names, at most 8 explicit record probes and a 2MiB shared pool. Native directory indexes and TreeSource inventory additionally use 16 index blocks, 32 entries/occurrences and depth 8. An independently assembled 512KiB seed has a resident INDEX_ROOT, INDX allocation with USA, resident bitmap, full UpCase and two hard-link name occurrences; `fixtures/ntfs-index-generator.*` records its exact constructor and SHA256. A required smoke reaches index-allocation traversal, native hard-link identity and retained deferred tree reads. Torn INDX, missing bitmap and invalid child-VCN seeds reach structural rejection. UserNamespace fuzz inventory is an explicit policy probe, not a full system-stream capture claim.

The undo target covers external journal v1 inspection and recovery in disjoint 64KiB target and bounded journal memory stores. Its independently assembled headers/body and provenance are archived in `fixtures/undo-generator.*`. Each input runs raw and with only SHA256 integrity fields recomputed, keeping mutated version, state, reserved bytes, binding, range and count fields intact so deeper preflight is reachable. Limits are 32 patches, 128KiB body, 256KiB shared memory, and 1MiB encoded input. The target asserts full resource refunds and unchanged target bytes on errors reporting no attempted writes. Dedicated smoke verifies actual rollback and idempotent recovery, and rehashed range/count failures before writes. It does not claim disk durability or failure-injection recovery coverage.

All twelve targets are discovered by `targets.json`, seed dispatch, replay dispatch and automatic Cargo bin discovery. Filesystem harnesses cap input at 1MiB. exFAT uses a fixed logical 2MiB zero-padded image without allocating that suffix; NTFS uses the exact input length. Harnesses have input/read/output budgets and do not depend on another project’s fuzz package. Malformed input is expected; panics and oracle mismatches are findings. Seeds include structural inputs and regression fixtures where available. Production defaults remain unchanged.

Run `cargo test --manifest-path fuzz/Cargo.toml --locked` and `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings`. Install honggfuzz 0.5.62 plus GCC/binutils/libunwind/liblzma development libraries, then run `python3 scripts/fuzz-campaign.py --iterations 10000`. Replay with `cargo run --manifest-path fuzz/Cargo.toml --locked --bin replay -- TARGET FILE`.

The weekly/manual workflow instruments code and retains seed/source hashes, tool versions, raw logs, summary counts, and findings even on failure. Each case has a five-second timeout. Bounded smoke campaigns do not establish absence of bugs or replace sustained sanitizer campaigns. Fuzzing operates only on memory or temporary files created by the harness; no input-supplied host paths are opened.

The NTFS target also invokes the complete base-record allocation/reference audit with ceilings of2048clusters,128records,1024attributes,256ranges,128entries,32indexblocks,depth8,50000workunits,64findings and64free ranges in the same2MiB pool. The independently hand-authored524800-byte fixture includes system streams, MFT and volume bitmaps, the MFT mirror, backup boot sector, full UpCase and native INDX references. Its constructor and exact SHA256 are archived as `fixtures/ntfs-clean-generator.*`; a required smoke verifies1024clusters,335allocated/owned clusters and18allocated records, clean evidence and reservation refunds. Mirror damage, lost allocation and referenced-free seeds exercise rejection or findings without free-space proof. This audit does not replay the log or imply complete system-stream capture.

The XFS target covers the explicit v5 leaf allocation/inode btrees, inline extent forks, shortform nativebyte directories, clean-log profile, checksum validation and complete allocation/reference audit. The independent1MiB four-AG constructor and provenance are `fixtures/xfs-generator.*`. Opening is bounded by8AGs,256inode slots,4096metadata records,256extents,65536work units and65536log bytes. Audit limits are4096blocks,128entries,65536work units and64findings; tree inventory uses32objects,64names and depth8 with a4MiB shared pool. A required smoke proves complete clean accounting, sparse zeros, exact payload bytes and shared hardlink identities, deferred reads after inventory drop, EOF cancellation and refunds. Damaged primary/secondary superblocks, inode CRC and truncated seeds exercise rejection. The former nine-target instrumented receipt precedes this target; a twelve-target campaign is required for the new snapshot.

The flash target exercises the owned logical NOR emulator through a mutable Storage backend. Inputs are capped at 64KiB, the logical image is 1024 bytes, and at most sixteen eight-byte operation records follow an eight-byte geometry/fault header. Operations program, erase, read or flush; the harness checks legal bit transitions, unchanged bytes on preflight rejection, accepted/verified progress and sticky uncertainty after attempted failures. Six control seeds cover success, torn writes, flush failure, forbidden transitions, unsupported NAND and insufficient budget. Scratch is 32 bytes, operations are capped at 64 bytes and the resource pool at 16320 bytes. Input, observed image, durable image and comparison buffers belong to the harness outside that pool. Fourteen required smoke tests cover the twelve targets; fresh instrumented campaign evidence is still required.

The JFFS2 target scans each input under explicit LE and BE logical NOR profiles (4096-byte erase blocks, four-byte programming, FF erased state). Input and scan are capped at 1MiB; opening limits are256 nodes,64 inodes,256 fragments,8192 native bytes and100000 work units, with a4MiB pool. Namespace audit caps256 entries,1024 work units and32 findings. At most eight directories and sixteen retained files are probed; file reads are bounded, deferred after tree drop, and checked after cancellation. Each input exercises strict NONE/ZERO and explicit RTIME/ZLIB readers. Compressed nodes are capped at4096 encoded/decoded bytes each,1MiB total encoded/decoded bytes and2MiB byte work. Ten independent seeds include both byte orders, valid RTIME expansion, checksummed malformed expansion, CRC damage, invalid compressed data, oversized node length, truncation and erased-only input. `fixtures/jffs2-generator.*` archives the original constructor and provenance; the additive RTIME constructor is in src/jffs2.rs. Required smoke proves exact overlap/truncation/zero reconstruction, positive compressed lazy reads, clean accounting and resource refunds. The compressed extension still requires a fresh mutation campaign. Other codecs, NAND and physical flash failure behavior remain outside this reader profile.

A twelve-target instrumented snapshot completed1002 iterations per target with
zero crashes/timeouts at `/data/cache/partmgr-fuzz-jffs2-source-jyc7nvyg/campaign-bfd-dev/summary.json`.
The adjacent `source-audit.json` confirms every recorded snapshot source hash.
On this Nix host the successful dependency environment was `nix-shell -p
binutils-unwrapped.dev libunwind xz gcc`; binutils alone did not expose bfd.h.
This receipt covers the retained source snapshot and predates later namespace
and builder additions.

The `hfsplus` target accepts at most 1 MiB and exercises the bare HFS+/HFSX
reader, complete allocation/reference audit and common tree. Its independent
specification fixture covers indexed catalogs, an overflow ninth extent and
separate resource forks. Five seeds include both catalog profiles, lost
allocation, primary/alternate header disagreement and truncation. The harness
uses an 8 MiB resource pool and bounded node/record/extent/work limits, checks
untrusted free-range bounds, both forks, deferred EOF, cancellation and refunds.
The positive smoke requires a clean audit and a two-stream file; accepting only
opening errors would fail that smoke. Instrumented campaign evidence must be
recorded separately; these smoke tests are not a campaign claim.

The HFS-expanded 13-target instrumented campaign passed 1,002 iterations per
target with zero crashes/timeouts at
`/data/cache/partmgr-hfs-fuzz-source-dk_0ced8/campaign-rust199/summary.json`.
The adjacent source audit verifies 154 source hashes against that isolated
snapshot. These bounded runs cover the captured profiles; they are not broad
format compatibility or security qualification.

The `hfs` target covers classic HFS separately from HFS+/HFSX. It accepts at most
1 MiB, uses an 8 MiB pool and bounded decode/audit/namespace limits, and retains
exact byte names with data/resource forks. Five independent seeds exercise clean
indexed catalog/overflow topology, lost allocation, alternate MDB disagreement,
bad block geometry and truncation. Free-range alignment is relative to the
allocation arena, which begins after the MDB/bitmap rather than at volume zero.
The positive smoke requires clean audit and two-stream reachability; retained
streams are checked for cancellation at EOF and all leases must refund. The
14-target instrumented campaign remains pending; 16 ordinary smokes pass.

The 14-target reader/storage campaign passed 1,002 iterations per target with
zero crashes/timeouts at
`/data/cache/partmgr-classic-hfs-campaign-t0qgy0k9/summary.json`.
Its adjacent source audit verifies 165 captured source hashes. The campaign
includes classic HFS, while owned JFFS2 append/GC fault coverage remains separate.
Package checks of this development capture failed and are recorded in the
progress log; the campaign result does not imply package acceptance.


Owned JFFS2 fuzz cases additionally declare erased capacity up to a 64 KiB
minimum on aligned inputs, then edit existing regular inode2 through the
multi-node range API. Payload is at most160 bytes, per-node data64 bytes,
external journal32 KiB and pool8 MiB. Positive both-endian smoke reaches three
NONE data nodes plus an explicit ZERO extension gap, seven-byte short program
writes, stale handle rejection, complete audited reopen and exact independently
modeled payload. Bounded namespace checks compare observed hardlink identities
without assuming fuzz-mutated names equal the original fixture. All leases
refund on rejected and completed cases. This uses functional modeled flushes;
native persistence cuts and a fresh instrumented campaign remain separate.

The same bounded range harness now explicitly opens RTIME and ZLIB owned
profiles for both byte orders. Independent RTIME256-byte histories must reach
range commit, generation invalidation and exact-profile COMPLETE recovery, then
full payload/hardlink reopening with opt-in immutable decoding. Strict recovery,
mismatched decoder-work caps and unknown codecs in both rehashed version2
headers must reject with instrumented zero target/journal write attempts and
unchanged bytes. Matching COMPLETE recovery also attempts no writes. Per-input
size1MiB, retained old file≤2048bytes, 8MiB pool,32KiB journal and reader/codec
work ceilings bound all paths; leases refund after success and rejection.

All26 ordinary fuzz smokes and strict all-target fuzz Clippy pass. Frozen
JFFS2 instrumented campaign
`/data/cache/partmgr-compressed-owned-fuzz-campaign-s67i1s17/summary.json` passes
1001 iterations with zero crashes/timeouts,237 snapshot sources and222 campaign
bindings verified by its adjacent root audit. It includes the new compressed
owned range/recovery paths; exhaustive interruption/native gates remain
separate. Full root Clippy on this capture rejects an unused staged ext JBD
bootstrap module and is explicitly failed evidence, independent of fuzz checks.

The expanded all16-target instrumented campaign at
`/data/cache/partmgr-compressed-owned-all-fuzz-campaign-s67i1s17/root-audit.json`
also passes1001 iterations per target with zero crashes/timeouts, unchanged
237-file snapshot/222 campaign bindings and retained corpus/log verification.
This refresh includes compressed owned JFFS2 range/recovery and the modern ext
reader while preserving the explicit failed full-root Clippy result for staged
unused bootstrap code at this snapshot.

APFS now appends eight independent native free-queue seeds without changing
older corpus indexes. Ghost and explicit retired extents in IP/main allocation
arenas are checked for exact counts/transaction/domain/overlap/current-owner/
free-bit semantics; conflicting proof cannot publish free ranges. Fifteen seeds
and322 immutable source files are retained for the APFS campaign at
`/data/cache/partmgr-apfs-queue-fuzz-campaign-14w5ijjt/root-audit.json`, passing1001
iterations0crashes0timeouts. All27 fuzz smokes and strict all-target fuzz Clippy
pass. Shared fixture reuse avoids loading the base APFS construction twice.

The APFS target now also opens bounded input through exclusive borrowed
`Storage` preparation, without an immutable `ReadAt` alias. Writes/barriers
panic in that harness; successful preparation requires a clean audit, rejects
stale directory identities and cancellation, leaves target bytes identical and
refunds reservations. A positive independent seed test proves valid opening.
The preparation work allowance matches the editor's conservative preflight;
input remains capped at2MiB,512 blocks,64 metadata blocks and65 attempts.
This does not fuzz committing mutations or recovery.

Frozen evidence
`/data/cache/partmgr-apfs-owned-fuzz-campaign-xjpdc0zh/root-audit.json`
binds358 snapshot files,231 campaign source hashes and15 seeds, with1001
iterations/no crashes/no timeouts. All28 smoke tests and strict fuzz Clippy pass.
The earlier tvd0o9wm snapshot failed its positive seed because its declared work
allowance was insufficient; that failed result remains unchanged. Full root
host checks and subsequent private-engine changes are outside this receipt.

The positive preparation regression additionally requires successful owned root
directory access, so an editor opening that skips the stale-identity/cancellation
checks cannot satisfy it. The strengthened regression, formatting and strict
fuzz Clippy pass on the current tree; the earlier instrumented receipt retains
its original frozen source scope.
