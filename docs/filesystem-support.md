# Filesystem support and dependency status

This matrix records the development implementation inventory (2026-10-08).
A planned profile is not operational support.
Update an operation only when its code and independent evidence meet
`FILESYSTEM_PLAN.md`; attach the evidence record. The specification/profile
inventory is in [filesystem-specifications.md](filesystem-specifications.md).

The current tree now includes `fs_core` lossless names, metadata/capability/source
contracts and shared cancellation/budgets; `fs_storage` owned bounded sessions,
immutable bounded sources; and `fs_file::ExtentFile`
for indexed uncompressed positional reads. Focused `fs_core`, `fs_storage` and
`fs_file` tests cover names, accounting, boundary rejection before mutation,
short/uncertain writes, flush failures, raw read-after-write/lock retention,
nonzero-region translation, sparse/unwritten ranges, map limits, random and
concurrent access. Root verification reports these tests and clippy passing.
The actual `ImageWriterSession` now lives in `fs_storage` and passes raw/QCOW2
consumer tests using published virtdisk 0.2.0. Its plain wasm gate regressed on
unconditional entropy dependencies; the sibling portability plan records that
open gate. The new partmgr API still requires a future release.
`fs_fat` adds geometry, bounded chain reads, exact native directory lookup and
VFAT decoding. `fs_fat_tree` inventories bounded trees and exposes deferred common
streams; native timestamps are explicitly opaque. `fs_fat_builder` adds a
deterministic nested VFAT new-output profile. `fs_fat_audit` accounts cluster
ownership and status under explicit work limits; its diagnostic coverage is
documented separately. Content-only FAT copy preflight and independently reopened
staged output are implemented. Observed generated EFI application execution on
GPT and MBR is recorded in the separate firmware gate. `fs_ext` and `fs_ext_tree`
provide a strict clean classic ext2 reader and bounded tree source. See the FAT,
ext2, copy, optical and native validation documents for exact scope.
`fs_image::ReadImage` now dispatches explicit read profiles with separate
allocation evidence and guarded deferred streams. `fs_exfat_builder` and
`fs_exfat_copy` provide deterministic staged direct authoring and content-only
capture; `fs_fat_edit` provides owned range replacement, extension and truncation
with staged external undo, refreshed ownership audits and checked reserved FAT encodings. Their documents bind
native receipts to exact sources. The NTFS base-record allocation/reference audit
is complete; advanced NTFS profiles and broader mutation operations remain open.

`fs_flash` adds a declared mutable flash contract and an owned logical NOR
emulator enforcing erased value, program transitions, alignment and bad blocks.
Six tests include48 modeled write cuts. This supplies no JFFS2 codec or physical
NAND/OOB/ECC backend; see [flash storage](filesystem-flash.md).

Numeric performance release thresholds remain unverified.

| Family/profile | Recognition/strict open | File/metadata access | New build | Existing edits/recovery | Independent/performance/native evidence |
| --- | --- | --- | --- | --- | --- |
| FAT12/16/32 and VFAT | Baseline geometry, chain/slot validation and bounded ownership audit | Indexed chains, exact native namespace/VFAT, tree source; timestamps opaque | Nested VFAT trees with deterministic aliases/default metadata; staged content-only copies | Owned file-range replacement, extension, truncation, file/directory creation, rename/move and file/empty-directory deletion with staged external undo; broader profiles remain open | Nine fsck/mtools authoring profiles and bounded-region copy pass; separate generated EFI GPT/MBR runtime gate; 705 earlier native range/resize cases and904 namespace cases (877 faults), with restart models tested separately; broader performance/recovery gates remain |
| Clean single-FAT exFAT revision 1.00 | Both boot checksums, bitmap/upcase validation and bounded namespace; full bounded ownership/state audit | Exact UTF-16 names, indexed chains/contiguous files, valid-data zero tails and tree source | Deterministic nested UTF16 direct builder; explicit content-only common-tree staged copies | Owned replacement, VDL initialization, zero extension, FAT conversion, truncation and empty files with external undo and dirty-state fencing; creation, directory growth, rename/move and file/empty-directory deletion implemented; ClearToZero-set writes excluded, TexFAT separate | Native exfatprogs/TSK initialized payload checks and native FAT destination validation; native zero-tail oracle gap documented |
| NTFS 3.1 clean-marker, sector 512 | Boot/MFT/USA/base attributes checked; complete bounded base-record allocation/reference audit; journal validation absent | Indexed resident/nonresident unnamed DATA, sparse/unwritten zeros, exact UTF-16 FILE names/sequence identities; native $I30 index traversal and explicit policy-scoped tree source | Planned staged profiles | Planned journal/system-file work | Independent mkntfs/ntfscp + TSK directory/payload checks, direct ISO/UDF capture +7z; malformed index fixtures and fuzz; broader native/performance gates remain |
| Clean classic ext2, 1/2/4 KiB blocks, 128-byte inodes | Explicit feature allowlist; checked groups/maps; full allocation/reference audit | Indexed indirect/sparse reads; byte names, UID/GID, mode/flags, opaque timestamps, hard-link identities and exact unfollowed symlink targets; tree source | Deterministic classic ext2 direct builder and common-tree content-only capture, explicit caller metadata defaults and preserved hardlinked objects | Owned range replacement, sparse allocation, extension/truncation, create, rename/move and unlink/delete with staged external undo and restartable recovery | Source-bound 5001-case e2fsck/debugfs owned-edit gate; eight e2fsck/debugfs builder images; handcrafted/native e2fsprogs audit and reader fixtures; native optical content-only capture; bounded raw-read benchmark; advanced features remain gated |
| Bounded ext3/JBD2 and extent-enabled ext4, 128/256-byte inodes | Explicit feature gates; clean inactive journal validation and complete allocation/reference audit | Checked indexed extent trees, data/hole/unwritten maps, native byte names and audited common tree; explicit facade/CLI opt-in | Classic ext2 destination only | Existing editor rejects these source features; native journal mutation planned | Source-bound extended-inode/timestamp and inactive-journal checksum native profiles; positive extent fuzz and instrumented campaign; independent CLI destination payload/hardlinks; the separate modern default-format profile below has frozen immutable acceptance; writable modern operations remain under development |
| Bounded modern ext4 metadata-checksummed profile | Checked low32-bit addresses,64-byte group descriptors,256-byte inodes, checksummed metadata/bitmaps, flex/uninitialized groups, indexed directories, resize/orphan references and inactive internal journal | Immutable public reader, complete audit, exact native byte names, hardlinks, inline/external xattrs and retained file maps; Ext facade required | Classic ext2 capture with explicit metadata defaults | Native journal editor/replay under development; classic editor rejects this profile | Root-audited six1/2/4KiB checksum-seed native cases; separate frozen603-payload/name capture and compact-map retention regression; larger addresses, unsupported feature combinations, writable journal and release-wide evidence remain open |
| XFS v5 leaf/inline/shortform, formatter-fresh log | Checked geometry, CRCs, single-leaf AG trees and complete bounded allocation/reference audit | Native byte names, hardlinks, indexed sparse/unwritten files and deferred tree source | Planned | Planned log/reference work | Six portable tests and independent xfsprogs 6.19.0 read/audit/payload/framing gate; broader trees, directories and ordinary mounted logs unsupported |
| Bare clean classic HFS, alphanumeric native comparison | Checked MDB, indexed catalog/overflow trees and complete bounded allocation/reference audit | Exact byte names, indexed data/resource forks and audited common tree | Planned | Planned external recovery | Five ordinary tests, facade and instrumented reader fuzz; native hfsutils catalog/free-count/two-fork oracle with compiled source/tool binding; broader collation, wrappers/self-overflow and macOS validation open; TSK rejects classic HFS |
| Bare nonjournaled HFS+ ASCII-fold / HFSX binary UTF16 | Checked volume headers, indexed catalog/overflow trees and complete bounded allocation/reference audit | Native UTF16 names, indexed data/resource forks and audited common tree; hardlink indirection and populated attributes rejected | Planned | Planned journal work | Five ordinary reader/audit/tree tests, facade and instrumented fuzz; hfsprogs-formatted Linux images with independent TSK payload/fork checks; fsck device-ioctl and macOS gates remain open |
| APFS single-store, bounded multiple-volume and retained-checkpoint profile | Checked complete checkpoints, maps/trees and full bounded spaceman/reference audit across all advertised volumes and structurally complete retained checkpoints; case and normalization sensitive, unencrypted | Native byte names, sparse indexed data, resident resource forks and audited tree/facade with explicit volume OID | Bounded1..128MiB native offline authoring from common trees, explicit metadata defaults, hardlinks, sparse bytes and embedded forks≤2048bytes; root-audited v12 native internal-tree image | Owned single-volume/single-leaf range/create/replace/truncate/link/rename/move/unlink COW with typed anchor and cold recovery; one-transaction retained-history profile, broader mutation/reclamation open | Frozen reader/sharing tests; source/tool/binary-bound apfsprogs/TSK native checker, allocation and complete single-volume payload oracle plus sparse two-volume/history oracle; regular hardlink identities and both native clone representations verified with exact refcounts; macOS and broader evidence open |
| Linux JFS v1/v2, 4 KiB, bounded single-IAG/level-zero maps, inline redone log | Checked superblocks/log state, inode maps and complete bounded allocation/reference audit | Exact UTF16 names, indexed sparse/unwritten extents, hardlinks, indexed directories and audited common tree/facade | Planned | Planned journal work | Five ordinary tests, facade audit-policy/stale-stream tests and fuzz smoke; jfsutils formatter/fsck/debugger gate passes; independent whole-file extraction and broader profiles remain open |
| JFFS2 declared logical NOR, none/zero nodes | Explicit LE/BE geometry, complete checked node scan, CRC/version reconstruction and reachable namespace audit | Native byte names, hardlinks, unfollowed symlinks, deferred indexed data/zero reconstruction | Deterministic common-tree offline builder with native names, hardlinks, unfollowed symlinks and explicit defaults | Owned append/shrink, create, hardlink, rename/move, unlink and live regular/symlink relocation/erase GC with bound intent recovery; inode-preserving multi-node range writes and truncation; bounded multi-node GC relocation into pristine erase blocks; NAND excluded | Frozen multi-node GC checkpoint includes mutation/recovery cuts across four persistence combinations and rehashed zero-write negatives; mtd-utils CRC and declared-LE Jefferson full range/GC payload gate; instrumented range fuzz; native truncate semantics, partially occupied-block allocation, kernel-mount oracle and advanced nodes remain open |
| JFFS2 explicit RTIME/ZLIB logical NOR | Complete bounded encoded CRC, exact expansion/stream validation and clean namespace audit; caller supplies codec caps | Lazy per-node decoding, native common tree and retained source/cancellation guards; no retained payload cache | Explicit RTIME/ZLIB deterministic common-tree authoring, root-audited24 native images across codecs/endians/ZERO/enumeration; NONE fallback and worst-case preflight | Strict default remains NONE/ZERO; explicit compressed owned range/truncate/create/replace/GC and exact-profile v2 recovery; native range/GC/error recovery, portable fault matrices and instrumented range/recovery fuzz pass | Root-audited final codec receipt covers LE/BE, twenty-four compressed nodes per case and full 98,304-byte Jefferson payloads; other codecs, mounted kernel semantics and hardware flash remain open |
| UDF (`libmkiso` development integration) | Retained bounded positional source | Deferred common file/stream handles, ICB identities and inspected native metadata; classified data/hole/unwritten maps; native topology and tree source | Staged common TreeSource with deferred file/named/root/system streams; ContentOnly explicit; RequireMetadata rejects | No framework editor | Raw/compressed QCOW2 R1 reads and streamed writer tests; partmgr release and preservation gates remain |
| ISO9660/Joliet/Rock Ridge (`libmkiso` development integration) | Checked cursor over retained bounded source | Selected native namespace/parent topology, tree source and deferred common file handles | Staged common TreeSource, explicit name conversion/content-only metadata, Rock Ridge hard links | No framework editor | Raw/compressed QCOW2 reads and staged writer tests; partmgr release and preservation gates remain |

No family row grants all historical/vendor variants. Dirty/recovery-required,
encrypted, unsupported incompatible features, uninspected metadata, auxiliary
devices and resizing each need explicit outcomes. Recognition, local validation,
global ownership audit, payload decode and durable commit are separate evidence.

## Initial API/dependency review

Read-only inspection of sibling source trees establishes APIs present locally;
it does not establish publication on crates.io. Current partmgr manifest uses
`virtdisk = "0.2.0"`, without a sibling path dependency.

| Owner/local version | Actual inspected API | Features | Required adapter/refactor and compatibility | Minimum published API version/evidence |
| --- | --- | --- | --- | --- |
| `virtdisk`, local 0.1.0 | `ReadAt: Send + Sync`, fixed `len`, positional reads; `DiskView::new(Arc<dyn ReadAt>, start, length)` | Core, no CLI required | Immutable stable-source adapter retains provenance/budgets; never implement this immutable contract on an editor handle | Existing dependency 0.1.0; new required API version none identified; publication of local extras not established |
| `virtdisk`, local 0.1.0 | `ImageWriter::{open,open_chain,read_exact_at}`, `WriteAt::{len,write_all_at,write_zeroes,flush,discard}`, `InspectImage`; writer also has resize/snapshot management | Core | R4 owned session retains writer privately, bounds all operations; map successful all-write to full `usize`; errors may leave uncertain mutation; retain advisory-lock/backing-parent and flush limits | R4 implementation must compile against locked crates.io dependency; local signature alone insufficient |
| `partmgr`, local 0.1.0 | `storage::Storage::{len,read_exact_at,write_at,flush}`, mutable short-write semantics; `WritePlan` checked staged replacement | Core | New bounded session bridge; preserve error/durability semantics. Do not reuse nonoverlapping table plans as universal filesystem journal transactions | Current owning tree; release evidence pending |
| `libmkiso` in `mkiso-rs`, local 0.1.1 | `UdfReader<'a>::open(&'a [u8], UdfLimits)`, `entries`, `extract`, size-bounded `read_entry`; UDF allocation extents private | Readers available with no default features | R1 positional retained-source input, bounded file/stream read and hole-aware extent visitation; retain slice/extraction wrappers | Unknown; local 0.1.1 is not evidence R1 published |
| `libmkiso`, local 0.1.1 | `IsoReader<R: Read + Seek>`, `index`, `into_parts`; `IsoIndex.extents: Vec<Vec<IsoExtent>>` | Readers available with no default features | Checked independent cursor over bounded immutable input; public index already supports positional payload adapter, new ISO input trait unnecessary | Current APIs local; required published version must be established by release build |
| `libmkiso`, local 0.1.1 | `UdfImage::{add_file,add_bytes,add_sparse_file,add_named_stream,add_root_stream,add_system_stream,write_with_cancel}`; ISO writer entry points take host directory | `native-writer` (default); `cli` additionally for `boot_media` | R2 library-owned stable deferred file-tree source, bounded inventories/content and staged emission; preserve host/buffer wrappers | Unknown pending R2 release |
| `libmkiso`, local 0.1.1 | `UdfEntry` kind/stream/ICB/raw name/link/size, no exposed timestamp/ownership/permission fields; `IsoEntry` raw name, selected `UnixMetadata` and link target | Reader core / writer `native-writer` | R3 per-profile read/write metadata and preservation matrices; absent differs from uninspected, inspected differs from reproducible | Unknown pending R3 release |

Framework storage/core must remain independent of partition codecs and optical
engines. The higher integration layer can depend on both filesystem contracts and
`libmkiso`; `libmkiso` must not import filesystem engines or `virtdisk`.

The table above records the initial local 0.1.1 optical API review. Current
development integration uses additive positional-source, metadata and deferred
tree APIs from published libmkiso 0.1.4. See
[optical reads](filesystem-optical-read.md) and
[optical writes](filesystem-optical-write.md) for exercised APIs, feature flags,
tests and command-only partmgr override. Published libmkiso 0.1.4 passes tests,
Clippy and independent native read/capture gates without a mkiso-rs override.
The earlier wasm gate passed with virtdisk 0.1.0; the current virtdisk 0.2.0
plain wasm build fails on getrandom and needs the sibling portability follow-up.
Only the new partmgr APIs still need a verified published release.

## Evidence gate checklist

For every advertised operation record its profile/feature allowlist, immutable or
exclusive-session preconditions, metadata classes and opaque limitations,
resource bounds, cancellation and uncertain-write outcome, recovery unit/barrier
ordering, and supported backend/publication durability. Native fixture and
failure tests must establish those particular claims. Numeric performance limits
must be selected before release per workload/backend, with cold/warm method,
hardware, tool versions, cache budget, concurrency, I/O counts/amplification,
latency, memory and durable throughput. None are established by this ledger.

Run fmt, all-target/all-feature locked clippy with warnings denied, and all-feature
locked tests in changed Rust repositories. Optical changes also retain
no-default-features tests, no-default-features+cli tests, and portable wasm check.
Independent filesystem validation, Windows capture/servicing, QEMU/OVMF boot,
power-loss durability and physical flash each remain separate gates.

`fs_undo` supplies a bounded external recovery protocol with explicit binding,
pre-mutation saved bytes, terminal markers and restartable restoration. It is
not a format engine's allocation/namespace transaction. Portable fault cuts and
native FAT16 payload restoration pass; create/delete/rename/allocation editors,
physical power-loss evidence and per-engine recovery audits remain required.

Accepted exFAT replacement/resize evidence is `/data/cache/partmgr-exfat-edit-native-20261008-frozen-v4/receipt.txt`; see [editor profile](filesystem-exfat-edit.md). XFS reader evidence is `/data/cache/partmgr-xfs-evidence/xfs-v5-leaf-inline-shortform-v1.txt`; see [exact XFS profile](filesystem-xfs-read.md). Subsequent namespace additions require their own gates. [Source scopes](filesystem-source-scopes.md) document engine identity domains.

FAT namespace final evidence: `/data/cache/partmgr-fat-namespace-native-20261008-final/receipt.txt` and source/binary verification.json; [namespace profile](filesystem-fat-namespace-edit.md). Native cuts cover continuing-owner recovery; deterministic tests additionally cover restart with retained/discarded unflushed writes. [Classic ext2 capture](filesystem-ext-copy.md) has separate content/name/hardlink native evidence.

ExFAT namespace evidence is `/data/cache/partmgr-exfat-namespace-native-20261008-generation-v4/receipt.txt` (51 retained payloads, root and subdirectory growth); existing replacement/resize behavior was refreshed at `/data/cache/partmgr-exfat-edit-native-20261008-generation-v6/receipt.txt`. JFFS2 offline builder evidence is `/data/cache/partmgr-jffs2-builder-evidence-final-2/jffs2-direct-tree-builder-v1.txt`: eight LE/BE × NONE/ZERO × enumeration-order images, independent mtd-utils input and Jefferson output checks, four portable tests. Flash append/GC remains a separate operation profile.

HFS+/HFSX native evidence is `/data/cache/partmgr-hfsplus-native-20261008-frozen-v4/receipt.txt`. The adjacent source verification checks all five engine/fixture/test hashes against the reviewed tree. TSK validates both independently populated native images, including resource forks; `fsck.hfsplus` exits 8 because regular files lack the required device ioctl, and macOS validation was not run. These gaps remain explicit.

Classic HFS frozen native evidence is `/data/cache/partmgr-classic-hfs-native-frozen-v4/receipt.txt` with compiled source/binary and start/end tool provenance in `provenance.txt`. The adjacent review verification independently compares 12 source/tool/build hashes. This validates the exercised hfsutils profile; it does not establish extended native byte collation, wrapper/self-overflow support or macOS fsck acceptance.


APFS frozen native evidence: `/data/cache/partmgr-apfs-native-v13/receipt.txt`.
Root's adjacent `root-audit.json` verifies all six archived source bindings,
start/end equality, image digest, command outcomes and independently calculated
16,397-byte sparse payload plus exact resource/nested data. TSK native inode
names are verified through istat; fls normalization-sensitive display is a
recorded gap. This is experimental Linux evidence, without macOS mount/fsck.
The adjacent multi-volume receipt and root audit also verify the 536,875,008-byte
sparse container, both native volume reports and 449 allocated blocks. Both shared-private-stream and distinct-stream clones also pass native checker
and full payload extraction with 203 allocated blocks and two hardlinks on the
original inode. Offline builder and owned COW operation evidence are recorded
separately below and in the builder/editor profiles.

Immutable ext profile evidence: [supported profiles](filesystem-ext-profiles.md)
and `/data/cache/partmgr-ext-profiles-native-20261008-metadata-final/receipt.txt`.
The explicit CLI opt-in additionally has an independent e2fsck/debugfs
complete-payload and exact byte-name hardlink destination oracle at
`/data/cache/partmgr-ext-profile-cli-oii0pk7s/native/receipt.json`. Default ext4
feature masks remain gated while their allocation semantics are implemented.

APFS standalone/GPT/MBR offline copy acceptance is recorded in
`/data/cache/partmgr-apfs-partition-native-0_vidunu/receipt.json`: frozen compiled
sources, native checker/full sparse data/resource fork, independent table
CRCs/type/extent and no-clobber retry. Both partition layouts also pass normal
and compressed QCOW2 full logical-disk equality and clean APFS facade reads,
with retained handles/cancelled EOF/refunds, in the root-audited receipts listed
in `docs/filesystem-storage.md`. These are immutable/offline pipeline results;
owned COW/recovery use separate editor gates. Complete independent
occurrence-name/macOS/firmware evidence remains open.

Owned APFS existing-length range COW native-v5 passes root audit of its exact
compiled source/executable/tool/artifact bindings, clean native checker and full
sparse-crossing data/resource fork/primary inode-link evidence. Cold restart
and interruption are separately covered by portable editor tests. Later
namespace/file-length operations have separate evidence below; reclamation and
macOS/firmware remain open. Root receipt:
`/data/cache/partmgr-apfs-edit-native-v5/root-audit.json`.

The initial single-volume/single-leaf owned APFS namespace and file-length
profile now has thirteen native operation cases, including sparse file/directory
creation, replacement, shrink/extension, link, rename/move and alias/last-link
file/fork or empty-directory deletion. Root audit
`/data/cache/partmgr-apfs-edit-namespace-native-v3/root-audit.json`
binds seventeen compiled sources and 1054 artifact hashes, with twenty-five
complete native stream models and clean read-only checker output after durably
torn boot-hint/cold-anchor recovery. This is one-transaction retained-checkpoint
evidence; queued-retirement reclamation, broader trees/multiple volumes,
snapshots/clones and macOS acceptance remain unfinished. See
[the exact editor profile](filesystem-apfs-edit.md) for constraints and portable
interruption tests; this native artifact audit does not prove those tests.
The v3 partial boot write does not independently prove a checksum-invalid boot:
its2048-byte prefix may contain all changed fields. A refreshed native gate must
retain the invalid boot and establish rejection before cold recovery.
That refreshed evidence is now root-audited at
`/data/cache/partmgr-apfs-edit-namespace-native-v4/root-audit.json`: thirteen
independently checksum-invalid saved boots/native rejections followed by clean
recovery and complete stream comparisons. Portable modeled interruption
evidence is separately bound at
`/data/cache/partmgr-apfs-edit-namespace-portable-cuts-v2/root-audit.json`
(fourteen compiled sources, twelve operations,1608 scenarios). Repeated owned
transactions and safe retirement/reclamation remain unfinished.

Explicit compressed JFFS2 owned range/GC/recovery now passes twelve native
RTIME/ZLIB × byte-order × normal/partial-program/partial-erase cases, including
24 complete independently modeled payload occurrences and unchanged framing.
Root receipt/source freeze is
`/data/cache/partmgr-jffs2-edit-codec-native-run4/root-audit.json`. Native FF names
use mtd-utils CRC/name output; Jefferson's own CRC-parsed parent/name query keeps
ASCII hardlink occurrences without changing its inode history/codec decoder.
Native historical shrinking-isize/kernel, other codecs/NAND/hardware evidence
remains open. Portable mutation/recovery matrices and instrumented owned fuzz
are separate complementary checks.
