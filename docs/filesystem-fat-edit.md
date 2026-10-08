# Exclusive recoverable FAT file editing

`fs_fat_edit::FatEditor<S, J>` owns an exclusive target `Storage` and an external
journal `Storage`. Opening performs a complete clean FAT ownership/state audit
against that same owned target, through the shared borrowed storage decoder. It
never adapts mutable storage to immutable `ReadAt`, never takes a whole-image
snapshot, and does not accept a detached audit report as write authorization.
The shared audit checks selected-copy reserved FAT media/entry-one encodings as
well as mirror agreement, dirty/error flags and namespace/allocation ownership.
FAT12 reserved entry one permits the specified EOC range; FAT16/32 status bits
are checked independently from their remaining reserved encoding.

The range operation replaces positional bytes within existing writable regular
files. `plan_extend_bytes` and `plan_extend` append bounded bytes or a deferred
immutable `FileRead`; `plan_truncate` shortens an existing file. Create, rename,
delete and directory growth remain required for the full FAT editing milestone.

Resize plans derive allocations solely from the retained complete clean audit.
Growth preserves existing logical content, fills all newly exposed bytes from the
append source, and zeros the remaining cluster tails. Stage one writes, flushes
and verifies initialized payload before stage two publishes FAT references,
first-cluster/size fields and FSInfo. The complete external undo body is durable
before either stage begins. Truncation releases only the opened file's verified
chain suffix; it preserves freed payload bytes and sets a zero-length file's first
cluster to zero. Neither operation rewrites the whole file or volume.

Packed FAT12 updates merge shared bytes while preserving adjacent entries. FAT16
and mirrored FAT32 update every selected copy; disabled FAT32 mirroring updates
only its active copy, retaining each entry's upper reserved nibble. Successful
resize commits refresh the complete audit before returning to `Ready`; failed
reinspection retains uncertainty and requires recovery. Old handles and competing
plans invalidate on transaction attempts exactly as for range replacement.

`resize_report()` states old/new lengths, allocated/freed counts, FSInfo
reconciliation and the explicit forensic timestamp policy. Names, aliases, LFN
slots, attributes and native time bytes are preserved. No current clock or guessed
FAT time encoding is substituted. Only allocation links, size/first cluster,
newly initialized payload/tails and FSInfo count/hint fields change.

FAT32 resize currently supports primary FSInfo sector one and declared backup
sector zero/six. Both present FSInfo structures must have valid signatures, zero
reserved arrays and in-range counters/hints; other layouts are `Unsupported`.
The planner computes the actual free count from the clean audit, writes an exact
post-operation count and a free-cluster hint (or unknown marker) to both copies,
and explicitly reports reconciling stale known counts. Unknown counts become
known. The backup FSInfo copy is allowed to have a stale count: Microsoft's
[primary FAT specification, sections 3.3 and 5](https://www.scs.stanford.edu/~zyedidia/docs/_other/fat.pdf)
states that ordinary implementations maintain only the primary FSInfo copy.

Deferred input reads are capped, handle short reads and recheck source identity
and length around each read. The caller must guarantee input immutability and
independence from the mutable target; identity checks cannot prove snapshots or
physical backend disjointness. Same-session input identities reject. Exhaustion,
insufficient space, cancellation and unsupported metadata fail during planning
without target writes. Plans retain undo data for every affected byte, including
formerly free-cluster bytes, so failures can restore the complete original image.

Open accepts a checked `(offset, length)` region, including a nonzero offset in a
larger raw image. All decoding, reads, patches and undo offsets remain relative to
that region. The wrapper rechecks container length and rejects ranges outside the
selected region. No public raw-write backend is exposed during the session.

`open_file` resolves exact native path components using the existing FAT decoder;
short aliases remain their original eleven bytes and LFNs remain UTF-16 units.
The resulting `FatEditFile` retains a checked indexed map and a source/generation
identity, with no backend capability. `read_at` accesses it through the editor and
uses an indexed extent search, without revisiting allocation chains. Read-only
attributes and directories explicitly reject this operation.

`plan_batch` accepts file handles, logical offsets and replacement byte slices.
It reads only affected before bytes and derives physical patches from checked
maps. It rejects empty, extending, overlapping, foreign or stale requests and
bounds request count, total bytes, extent visits and retained patch memory. A
`FatEditBatch` exposes immutable patches for review, with source/generation binding;
it cannot be constructed from caller-supplied physical addresses.

`commit` consumes a batch and uses `fs_undo::UndoPlan` with the owned external
medium. Saved old/new bytes and their integrity check precede publication of a
prepared marker; target replacement, flush, verification and committed publication
follow the undo protocol's explicit barriers. Only affected ranges are written.
A successful commit increments the editor generation and invalidates all older
handles and batches. Planning/preflight errors before a transaction attempt perform
no writes. A failed transaction attempt invalidates handles and enters
`NeedsRecovery`, blocking further reads, file opens, planning and commits.

Continuing-owner `recover` uses the retained transaction binding and external undo
recovery whenever target writes were attempted. If the retained failure proves
this owner attempted no target writes, it may clear and verify its failed journal
publication instead. The editor opened without a prepared obligation and exposes
no alternate mutation path to its journal, so that permission comes from the
actual transaction failure, not from an audit or a guessed filesystem state.
Both paths repeat the complete clean audit before returning to `Ready`.

`recover_open` restores/verifies a caller-bound persisted journal before auditing a
new session. Opening directly with a prepared journal rejects; an existing terminal
journal must match the supplied volume/region/session binding. Releasing stores
through `into_stores` returns the explicit uncertainty state and does not discharge
an obligation. No-target-write proof is not reconstructed after release: torn
headers without any intact record remain a recovery error on reopen. The fault
model verifies such unpublished cases leave target bytes entirely unchanged.

Ownership of two Rust values does not prove backend exclusivity, physical
disjointness or independent persistence. Storage implementors/callers must enforce
exclusive access, independently verify that target and journal are disjoint, and
verify the binding against the actual selected volume and region. Caller-assigned
transaction identifiers must be unique within the durable session binding.
`FileStorage` provides a locked regular-file implementation for the native gate;
other stores must honor `Storage` read/write/flush semantics. A binding is an
identity check, not authentication against maliciously rewritten journal bytes.

Accounting includes the retained audit, decoder directory scratch, checked maps,
file metadata and batch before/new bytes. Undo planning may briefly overlap its
own reservation with the planning lease, conservatively charging transfer. Memory,
request, patch, body, file-cluster and transaction-work exhaustion abort before
unauthorized target writes. Cancellation propagates through decoding, planning,
commit and recovery. Source counters and editor generations use checked increments.

## Verification

Ordinary tests use a separately assembled packed FAT12 image with a fragmented
file and an unrelated file. They check cross-cluster and multi-file batches,
repeated positional reads, stale/foreign scopes, generation changes, audit defects,
byte/work/patch limits, overlap/extension rejection, pending-journal gates and
complete reservation refunds. Every actual write and flush event is failed in a
continuing owner. Restart tests repeat every event with unflushed writes either
lost or retained, allowing only verified committed bytes or restored original
bytes. Invalid unpublished headers are explicitly rejected and accompany an
unchanged target. These deterministic tests model the declared protocol; they do
not qualify physical disk power loss.

The explicit native gate is ignored by default. Enable it with a fresh absolute
destination and all three tools available:

```sh
PARTMGR_FAT_EDIT_EVIDENCE=/absolute/fresh/destination cargo test --locked --test fs_fat_edit -- --ignored --nocapture
```

An enabled gate fails when tools or the destination are missing. `mkfs.fat` creates
FAT12/16/32 images independently; mcopy installs a deterministic 131,089-byte file
and an unrelated file. Each is embedded at byte 4096 of a larger raw container
with nonzero prefix and suffix. The editor replaces two small file ranges, crosses
cluster boundaries and verifies native family selection. Every native write and
flush event is separately failed by partial-write/flush-error injection, then
recovered in the same exclusive session. Every case compares the complete target
against the original or exactly authorized new image, proving all other payload,
metadata, allocation and out-of-region bytes are preserved. Native mcopy reads
through the actual nonzero image offset; `fsck.fat -n` checks an exact extracted
volume without repair. Both payload and whole-image hashes are retained.

The receipt records exact tool argv, executable paths/hashes, native stdout/stderr
and their hashes, family/cut/stage outcomes, original/new/recovered image and payload
hashes, unchanged-byte assertions, compiled test binary and source/lockfile hashes.
Independent seed images, committed containers, journals and final oracle artifacts
are retained; files and directory are synced before success. Native injected IO
failures exercise real regular-file storage, while the separate memory models
exercise the two declared persistence outcomes. Neither establishes firmware boot,
Windows servicing or physical power-loss correctness.

The enabled native gate passed on 2026-10-08 against the shared reserved-entry
validation and final editor implementation. Receipt:
`/data/cache/partmgr-fat-edit-native-20261008-reserved-final/receipt.txt`.
Each family passed one normal transaction and all 52 separately injected native
write/barrier cuts (159 total cases). Source and binary hashes and the case count
were independently rechecked against the retained receipt. Enabled missing-tool
and missing-destination controls both failed with exit 101 and no success receipt:
`/data/cache/partmgr-fat-edit-final-negative-li8k1bi_/control.json`.

Do not substitute a new empty journal when reopening a session with a previous
unresolved operation. The external journal and its verified binding belong to the
recovery obligation; a clean FAT allocation audit alone cannot detect partially
replaced file payload bytes.

## Resize verification

Thirteen ordinary editor tests include fragmented growth, EOF tail initialization,
truncate across a cluster boundary, zero/reallocation, packed-neighbor preservation,
out-of-space/cancellation/read-only gates, deferred short reads and stale length,
competing plans and complete refunds. An independently assembled FAT32 fixture
checks active-copy selection, upper reserved bits, byte-exact inactive FAT, primary
and backup FSInfo count/hint updates and invalid backup no-write rejection. Every
resize write/barrier cut runs in a continuing owner and after restart under both
unflushed persistence models.

The explicit resize native gate runs append, shorten, truncate-to-zero and append
to an empty file for independently formatted FAT12/16/32 images. Each operation
repeats every actual partial-write/flush-failure cut, recovering the same owned
session. Native mcopy independently compares payload bytes and fsck.fat checks
without repair; whole-container comparison permits only the reviewed patch set,
including allocation/size/FSInfo changes, and retains nonzero region padding.

```sh
PARTMGR_FAT_EDIT_EVIDENCE=/absolute/fresh/resize-evidence cargo test --all-features --locked --test fs_fat_edit native_fat12_16_32_resize_every_io_cut -- --ignored --exact --nocapture
```

Enabled missing tools/destination fail. Receipts retain exact commands, tool and
source hashes, native outputs, cut outcomes and before/after payload/image hashes.
The older range-only receipt establishes only positional range replacement.

The final range regression receipt is
`/data/cache/partmgr-fat-range-native-20261008-resize-final/receipt.txt` (159 cases).
The final resize receipts are under
`/data/cache/partmgr-fat-resize-native-20261008-final/{extend,truncate,zero,empty_extend}/receipt.txt`
(546 cases: 12 normal operations plus all 534 emitted failure cuts). These capture
source/lockfile and binary hashes once at top-level gate start. Final negative
controls at `/data/cache/partmgr-fat-resize-final-negative-z54rsz_8/control.json`
record exit 101 for both enabled missing-tool and missing-destination cases with
no success receipt, using the same compiled binary. These retained artifact paths
are execution evidence for this checkout; the explicit commands above reproduce
the gates with independently generated fixtures.
