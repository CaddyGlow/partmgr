# NTFS log record queries and active-window reconstruction

This is an implementation design for the remaining N2 work in
[the maintenance plan](filesystem-write-maintenance-plan.md). The implemented
[restart and physical-page inspection](filesystem-ntfs-logfile-design.md) is
the input foundation. This document does not establish recovery qualification.

The current integrated readonly analysis also includes exact source-derived redo
entry, admitted nonresident byte and bitmap effects, bounded runtime target
copies, and retained completed physical reads
([host binding](/data/cache/partmgr-ntfs-native-runtime-integrated-binding-20261012-v3.json)).
These physical shadow observations do not authorize disk mutation. FILE/MFT
cache effects are staged for host validation; source-derived MFT mirror range,
pending state and final mirror shadows also remain required. Remaining FILE/index
operations, ordered shadow-log reads, undo and durable recovery are N2 requirements.

## Pinned sources and interpretation

The primary reference is Linux v6.12 `fs/ntfs3/fslog.c`, commit
`adc218676eef25575469234709c2d87185ca223a`, SHA-256
`5d0f8866ef76ddfcda396916112be0e0382d2ee8ecffec21b97775c2a1c19264`.
The local copy is in `/data/cache/partmgr-maintenance-specs/ntfs-logfile/`.
Relevant immutable source locations are:

- [Restart geometry, lines 509–525](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L509): sequence-bit count follows file size; offsets and header lengths are quad-aligned.
- [LSN conversion, lines 1079–1140](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L1079): `lsn_to_vbo`, `next_page_off`, `vbo_to_lsn`, `base_lsn`, client bounds.
- [Record endpoints and successors, lines 1423–1517](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L1423): `final_log_off`, `next_log_lsn`.
- [Tail discovery, lines 1600–2239](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L1600): expected generation, transfer continuity, tail replacement and torn transfers.
- [Record assembly and lookup, lines 2246–2448](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L2246): `read_log_rec_buf`, `read_rst_area`, `find_log_rec`.
- [Restart initialization, lines 3940–4020](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L3940): pseudo LSNs, reuse position, oldest client and current endpoint.

These are independently implemented semantics to investigate and qualify, not a
Microsoft specification. Rust must use checked wide arithmetic rather than copy
the reference's narrowing C shifts or unchecked additions.

## Implemented component: caller-qualified restart candidate

`inspect_logfile_restart_candidate` owns both inspected restart copies and accepts
an explicit `NtfsLogRestartOrdering::NumericWithoutRollover` caller assumption.
`inspect_ntfs_logfile_restart_candidate` binds the same inspection to resolved
native record 2; its final volume source guard withholds a failed candidate.
It ranks compatible candidates by numeric `current_lsn`, including ordinary
sequence-generation increments, following
[pinned Linux restart comparison, lines 3847–3869](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L3847).
Sequence-counter rollover is excluded by the caller's profile, not detected or
ordered modularly by this inspector. Zero/pseudo LSNs are not record anchors.

Both valid copies must agree in version, file and sequence geometry, record/data
framing, client lists and immutable client identity bytes. Current, oldest and
checkpoint LSNs may differ. Equal-LSN ties additionally require identical complete
USA-fixed declared restart areas, including omitted/opaque fields and layout
metadata. Independent USA markers and padding outside the area are ignored;
copy zero breaks an equivalent tie. A fully read format-invalid copy may be
rejected in favor of a valid candidate. Incomplete reads, backend/resource errors,
cancellation and stale-source failures block fallback. Original rejected errors
remain accessible through the owned restart report; comparison work is bounded.

The optional selected index/context is a prerequisite for investigating tail
preprocessing. It supplies no active-window, checkpoint, fast-copy overlay or
recovery authority. Caller source immutability remains required.

## Integrated discovery and immutable overlay

The implementation additionally derives a source-owned discovery seed,
retains native tail-pair candidates and follows ordinary pages using the pinned
scanner's fixed-address lookahead. The reviewed nine-file integration patch is
`/tmp/partmgr-ntfs-discovery-integration-20261012-v1/changes.patch`, SHA-256
`927930f5a688f7075f1289fc3d9a15fea4d3d6f94653f7072be3905bf1833142`.
The nine files match the isolated snapshot that passed all five host checks in
`/data/cache/partmgr-combined-host-checks-20261012-v6/`. They are integrated in
the current worktree. All five repository checks pass in
`/data/cache/partmgr-ntfs-discovery-integrated-host-checks-20261012-v1/`, with
372 identical start/end/live source hashes independently verified.

`NtfsLogReadOnlyOverlay` retains scanner-selected replacements and their original
physical candidate provenance. It normalizes protected pages in native transfer
order and supplies immutable reads without writing the source. The successor
query assembles an actual record through that same overlay and selected restart
context before deriving its next-LSN observation. An aligned inclusive endpoint
remains explicitly unsupported. Neither report establishes active membership;
active-window and recovery completeness remain false.

The [focused host evidence](/data/cache/partmgr-ntfs-overlay-focused-checks-20261012-v3.json)
covers 16 framed-byte consumer tests, three successor arithmetic tests and
Clippy. This is separate from native Windows qualification. Later source-bound traversal, checkpoint and private analysis layers are recorded
below. Native active-window and recovery qualification remain open.
The scanner retains native partial-transfer arithmetic and replacement
consumption. The pinned source's residual count is a read-only
mount refusal condition; it does not authorize invented page-erasure cleanup.

The subsequent integrated scanner correction separates the fast-copy
normalization anchor from the terminal replacement shortcut. It also retains
fixed-address retry errors, planned partial-transfer counts and exact overlay
consumption without erasing pages. Its
[focused run](/data/cache/partmgr-ntfs-partial-transfer-focused-checks-20261012-v2.json)
passes 23 consumer tests and one consumption arithmetic test. The subsequent
[full repository gate](/data/cache/partmgr-ntfs-discovery-integrated-host-checks-20261012-v5/result.json)
passes formatting, all-feature Clippy and tests, and both portable checks, with
373 identical start/end/live source hashes independently verified. Complete
active-window and recovery authority remain open.

The integrated private physical traversal frames foreign-client and non-client
records while preserving strict public exact-client queries. It follows sealed
physical successors, retains failed steps and bounded prefixes, and rechecks
every retained query's restart copies and record pages plus the original overlay
guards. A transient restart-byte change followed by restoration is rejected.
Its [focused tests](/data/cache/partmgr-ntfs-physical-traversal-focused-checks-20261012-v2.json)
pass all 26 consumers; all five host checks pass with
[373 repository source hashes matching the tested snapshot](/data/cache/partmgr-ntfs-physical-traversal-integrated-binding-20261012-v1.json).
Skipped envelopes still require complete structural framing, which can refuse
inputs that native header-only skipping accepts. This traversal alone does not
establish transaction dependencies or recovery authority.

The subsequent integrated checkpoint selector reads the exact selected client
restart LSN, including records outside the oldest-to-current traversal. It
distinguishes zero restart LSNs from empty restart payloads, applies the native
checkpoint-start override, and begins the analysis suffix strictly after the
selected anchor. It retains failed direct queries and rechecks their restart and
record bytes under aggregate page, payload and work limits. The
[focused run](/data/cache/partmgr-ntfs-checkpoint-analysis-focused-checks-20261012-v2.json)
passes 33 consumers, and all five checks pass with
[374 repository source hashes matching the tested snapshot](/data/cache/partmgr-ntfs-checkpoint-analysis-integrated-binding-20261012-v1.json).
At that checkpoint snapshot, the embedded native-gate inventory matched its
232-file verifier inventory. Later private analysis and target layers extend the
inventory; native recovery qualification remains open.

The current integrated private pipeline loads transaction, dirty-page, name and
open-attribute tables in native order, projects the transaction suffix, and
updates source-owned dirty/open/name tables under combined work and memory
limits. A native context retains the exact physical reads consumed while opening
the volume and resolving record 2; equal bytes from another source handle do not
substitute for that identity. Target queries retain and repeat their own physical
observations, preserve original lookup failures, and expose matching native
attribute candidates or a missing-attribute provisional descriptor. Provisional
descriptors are in-memory intents; they grant no object allocation permission.

Unused FILE slots, sequence conflicts and targets beyond the logical MFT remain
unsupported observations because generic reader rejection does not decide native
cold-replay/cached-inode behavior. No owner or provisional descriptor is invented
for those branches. Initial names retain source order and duplicate replacement;
open-slot extension and subsequent dirty updates retain exact slot provenance.
Final guards repeat retained analysis, context and target observations.

All five host checks passed against the integrated 383-source snapshot in the
[target integration binding](/data/cache/partmgr-ntfs-target-intents-integrated-binding-20261012-v1.json).
These framed host tests establish the private observations and resource/source
checks described here. The subsequent reviewed 390-source integration adds
source-owned UpCase/list winner selection and physical run reconstruction for
admitted ordinary regular-file contexts
([binding](/data/cache/partmgr-ntfs-target-winner-integrated-binding-20261012-v1.json)).
Neither checkpoint establishes native Windows recovery. Directory index and
special-mode admission and cold/cached lookup ambiguities remain unfinished.
The reviewed 391-source integration adds source-ordered dirty LCN replacement,
shared unnamed DATA maps with per-open copied sizes, same-LCN bypass and native
redo-start derivation
([binding](/data/cache/partmgr-ntfs-target-dirty-runs-integrated-binding-20261012-v1.json)).
Exact redo traversal and effects, undo, durable publication and
full active-window/recovery authority remain required. The current per-layer
qualification record is maintained in
[the maintenance status](filesystem-maintenance-status.md).

## Implemented component: exact-LSN structural record query

The implementation provides checked LSN geometry and an exact-LSN record query before selecting an
authoritative active tail. This materially enables decoding the client's restart
record and checkpoint tables. Its result means only that one identified record
is structurally assembled from an explicitly supplied restart context; it does
not claim that its context is the selected recoverable generation.

A complete report also exposes `extent()` as an immutable
`NtfsLogRecordExtent`. `final_byte_offset()` is the inclusive physical stream
offset of the last payload byte, or the last of the 48 LFS header bytes for an
empty payload. `final_page_offset()` identifies its page, and `physical_wraps()`
counts only end-to-ordinary-start transitions actually traversed. Continuation
page headers and alignment padding are excluded. An endpoint at page EOF does
not itself add a wrap; a near-full-ring record may revisit its first page.
The observation is withheld if assembly or the final source/cancellation guard
fails. It does not establish an aligned successor, next LSN, generation change,
active membership or authoritative tail selection.

`inspect_logfile_record_links` now provides a source-owned bounded walk of either
`NtfsLogRecordLinkKind::Previous` or `UndoNext`; the native-volume wrapper is
`inspect_ntfs_logfile_record_links`. Each exact query uses the same caller-selected
restart copy, with identical original raw restart bytes and decoded client context.
Links come from immutable owned headers. There is no descending numeric-LSN or
transaction-ID equality requirement. Zero is an observed terminator; cycles,
nonzero unresolved targets and budget/source failures retain prior and failing
query evidence, the original stopping error and `pending_next_lsn()`.

`NtfsLogRecordLinkLimits` bounds records, aggregate restart/record pages, retained
payload and work, including repeated restart inspections, context comparisons and
cycle checks. Shared leases retain the reports. `complete()` and `ZeroLink`
termination mean only that this selected field reached zero with final stream and
volume guards passing. They do not prove complete history, active-window closure,
transaction analysis, undo execution or replay authority. The source must remain
immutable; length and restart checks cannot detect arbitrary same-length changes.

For the admitted 1.1 and 2.0 profiles with 4096-byte pages, let `D = 64 - sequence_bits`,
`offset_units = lsn & ((1 << D) - 1)`, `byte_offset = offset_units * 8`, and
`generation = lsn >> D`. Require the recorded sequence-bit count to equal the
file-size-derived value before conversion. Reject arithmetic overflow, offsets
outside the recorded usable file size, restart/tail-slot offsets and page-header
offsets. Zero and pseudo LSNs mapping before the ordinary region are distinct
observations, not record addresses. Ordinary pages start at byte 16384 for 1.1
and byte 139264 for 2.0. The next page wraps from the recorded end to that
version's ordinary start, never to a restart, tail or fast-copy slot.

An exact query should:

1. Decode the target address and lease a protected-page scratch buffer. Validate
   USA and supported ordinary-page framing before reading the 48-byte record
   header at the target offset. Require its `this_lsn` to equal the query exactly.
2. Retain `this_lsn`, client previous/undo-next LSNs, client ID, record type,
   transaction ID, flags and payload length. Preserve unknown types/flags with an
   explicit unsupported semantic outcome; do not fabricate NTFS operations.
3. Check header and payload length with checked arithmetic before allocating.
   Bound payload bytes separately from pages, record count, work and findings.
   A non-multipage record must fit the source page completely.
4. For a multipage record, copy only its declared payload. The first segment
   begins after the record header; subsequent segments begin at restart
   `page_data_offset`. Follow physical circular successors, validate each page's
   fixups and supported framing, and stop after at most the ordinary-page count
   plus one. A late starting record can return to its first physical page's
   prefix; the strict header-plus-payload bound below the complete ordinary data
   capacity prevents overlapping its own header or traversing a second ring.
   Never concatenate pages sorted by LSN or search arbitrary bytes for headers.
5. Enforce the source's continuation evidence: queried LSN must not exceed each
   page's ordinary header LSN; a nonfinal segment must not have header LSN equal
   to last-ended LSN; the final segment must have record-end evidence and a
   last-ended LSN at least as large as the queried LSN. These local checks are
   necessary but do not themselves establish an authoritative active window.
6. Retain exact page/byte provenance and original errors. Check cancellation and
   source stability before publication. Release all leases on every failure.

The endpoint helper should return an inclusive last byte, matching
`final_log_off`, with successor calculation kept separate. After an assembled
record, the reference computes `ALIGN(end, 8)` when another record remains on
that page. Because the helper documents an inclusive endpoint, the payload
length/alignment convention must be verified against native records before
adopting that expression; do not silently replace it with `align(end + 1, 8)`;
if the record equals the ending page's ordinary header LSN, advance to the next
page's data start. Increment generation for each physical end-to-start wrap.
Generation overflow must fail explicitly in a future successor iterator. Successor LSNs must progress strictly
within the chosen nonwrapping numeric interval; sequence-counter rollover is
unsupported until separately qualified.

The exact query intentionally does not require continuation page header LSNs to
increment generation at a physical wrap: `read_log_rec_buf` supplies no such
rule, and a continuing record can retain its starting LSN. Its supported checks
are the local numeric comparisons above. A successful query is structural byte
assembly, not proof of record membership in an authoritative active generation.
Raw page LSNs remain available for the later discovery state machine.

### Opaque page flag `0x2` in structural queries

The exact query permits page bit `0x2` as an opaque observation, separately from
the interpreted END bit `0x1`. Other unknown page bits remain unsupported. The
physical-page inventory retains its existing stricter semantic classification.
`complete()` and `payload()` describe structural assembly only;
`page_flag_semantics_supported()` is false when any contributing page has bit
`0x2`, and on every incomplete query. It never describes transaction coverage.

The pinned Linux implementation defines only END and masks it in
[`is_log_record_end`, lines 280–284](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L280).
Its page reader and exact record assembly neither reject bit `0x2` nor use it to
select an alternative payload layout. Pinned
[dfir_ntfs, lines 25–26](https://github.com/msuhanov/dfir_ntfs/blob/ec3ae0884048ade106c91a68dab7c9fb3af393bf/dfir_ntfs/LogFile.py#L25)
calls it `LOG_PAGE_UNKNOWN_2` and comments that it marks a client restart area
on versions 2.0+. That constant is never used by its parsing or assembly code;
[`LogRecordPage`](https://github.com/msuhanov/dfir_ntfs/blob/ec3ae0884048ade106c91a68dab7c9fb3af393bf/dfir_ntfs/LogFile.py#L464)
and [`get_client_data`](https://github.com/msuhanov/dfir_ntfs/blob/ec3ae0884048ade106c91a68dab7c9fb3af393bf/dfir_ntfs/LogFile.py#L1278)
use the same fixed-up bytes regardless of this bit.

The Windows-authored clean offline 1.1 fixture independently contains ordinary
page flags `3`, including the page at byte 143360 carrying current LSN 2639418
and oldest LSN 2639405. This contradicts treating the dfir version comment as a
universal restriction. It establishes observed bytes, not the bit's meaning.
No semantic interpretation, version constraint, recovery readiness or tail
selection is inferred from this structural allowance.

## Authoritative active-window selection

### Implemented borrowed client restart decoding

`inspect_ntfs_client_restart` requires a complete structural record with LFS
envelope type 2 and the independently validated NTFS client identity. It borrows
the payload without allocation or additional I/O. The allowlisted client payload
version is `(1, 0)`, independently of whether LFS itself is 1.1 or 2.0.
The mandatory 64-byte prefix follows pinned
[Linux `NTFS_RESTART`, lines 199–213](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L199):
checkpoint start LSN and four table LSN/byte-count references. Those references
are observations; zero sizes and unusual LSNs remain unchanged rather than being
treated as validated pointers or rejected by guessed constraints.

Optional extensions follow pinned
[dfir_ntfs `NTFSRestartArea`, lines 1508–1548](https://github.com/msuhanov/dfir_ntfs/blob/ec3ae0884048ade106c91a68dab7c9fb3af393bf/dfir_ntfs/LogFile.py#L1508):
signed USN restart offset at length 72, last LSN at 80, bytes per cluster at 84,
reserved bytes 84–87 at 88, USN file reference at 96, signed USN base at 104,
and oldest LSN at 112. A partial optional field is not exposed as a typed value;
the complete raw payload and extension bytes retain it. Bytes beyond 112 remain
available as unknown trailing bytes. This decoder does not follow a table,
validate table contents, select a checkpoint or establish replay readiness.

### Explicit-context component for the captured 2.0 dirty log

Structural exact queries admit version 2.0 through an explicitly selected
restart-copy index, inspected from the same source inside the operation. The
existing strict matching-copy query admits both versions only when decoded areas
match fully; divergent copies remain ambiguous. An explicit-context query must
retain both restart observations and identify which independently valid copy
provided geometry/client identity. This is context selection by the caller for
research, not an authoritative newest-restart decision. Use the admitted 2.0
ordinary start at page 34 and retain the opaque-page-flag distinction. Do not
apply fast copies as a side effect of querying a checkpoint.
The public `NtfsLogRecordQuery` carries the LSN and copy index;
`inspect_logfile_record_in_restart` and its native-volume wrapper use it.
Reports expose the requested index and independently validated restart context.
An unselected format error remains diagnostic in `restart()` and does not become
a stopping error on a completed explicit query. Any uncompleted restart read,
backend I/O, cancellation, source change or resource failure blocks the query.
A bad selected copy or an index outside zero/one never falls back silently.

The frozen power-cut stream
`/data/cache/partmgr-ntfs-windows-dirty-logfile-20261010-v1/pre-recovery-logfile.bin`
has SHA-256
`d027c26addbb038c896f493868d9da85a0b7a883933429bbcad11109496ec912`;
the pre-recovery partition has SHA-256
`e0ba3d1b1ca7b985a5632da57f404a70f6450ee8a4971ccd9d2e147c6cff687c`.
The frozen acquisition receipt has SHA-256
`39cebc61a16eb3683a5ad29316daf6a89aed83ea8fc523089bf285c4c323846d`.
Independent protected-page decoding yields these concrete counterexamples to
overly simple selection algorithms:

| Observation | Native bytes |
| --- | --- |
| Copy 0 restart anchor | LSN 4753128 at stream byte 276288; matching record `this_lsn`; ordinary page header LSN 4753384; page flags 3 |
| Copy 1 restart anchor | LSN 4839042 at stream byte 963600; matching record `this_lsn`; ordinary page header LSN 4839413; page flags 3 |
| Fast copies | All 32 have generation 9, also the newer restart's generation; their header LSNs exceed both restart anchors |
| Destination collisions | Fifteen fast-copy destinations occur twice, including byte 2162688 |

Thus both historical checkpoint envelopes remain available without an overlay,
while the larger restart LSN does not identify the most recent record endpoint.
The qualified explicit-context query establishes exact envelope/payload equality
against an independent parser for both anchors. Then decode `NTFS_RESTART`
payloads and their checkpoint/table LSNs. That progresses transaction analysis;
it does not replace the still-required selection, fast overlay, table validation,
redo/undo, durable writer and native recovery gates in N2.

### Selection and fast-overlay implementation order

### Next: referenced dump envelopes and restart tables

Follow each nonempty checkpoint reference through the same explicit restart
context and exact-LSN query; do not reinterpret a zero-byte reference as a
required read. The next borrowed inspector should decode the NTFS client record
envelope before interpreting a dump. Pinned
[Linux `LOG_REC_HDR`, lines 71–88](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L71)
places redo/undo operation, offset and length at `00/02/04/06/08/0a`, target
attribute at `0c`, LCN count at `0e`, record/attribute/cluster offsets at
`10/12/14`, reserved word at `16`, target VCN at `18`, and LCN array at `20`.
Crucially [`lrh_length`, lines 388–393](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L388)
requires `32 + 8 * max(1, LCN_count)` bytes, including one 8-byte slot even when
LCN count is zero. Check every product/range before borrowing. Offsets are
eight-byte aligned; retain reserved words and padding. A zero-length undo range
at the payload end is legitimate, not a missing byte read.

The source's dump operation codes are
[`OpenAttributeTableDump = 0x1d`, `AttributeNamesDump = 0x1e`,
`DirtyPageTableDump = 0x1f`, `TransactionTableDump = 0x20`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L327).
An envelope inspector may retain unknown operations opaquely, but a typed dump
inspector must require its expected operation and must not establish redo/undo
support merely by decoding offsets. Native dump records below have undo operation
zero, target attribute 24, transaction ID 24 and reserved word 2; zeroing or
rejecting that reserved word would destroy valid observed evidence.

The frozen dirty image gives these references and independent envelope facts:

| Context anchor | Open table LSN / bytes | Names LSN / bytes | Dirty table LSN / bytes |
| --- | --- | --- | --- |
| 4753128 | 4752875 / 344 | 4752937 / 46 | 4752954 / 1304 |
| 4839042 | 4838789 / 344 | 4838843 / 46 | 4838860 / 1304 |

All six are LFS type-1 client records. Redo begins at offset 40, with the expected
operation above; payload lengths are respectively 384, 88 and 1344. Undo length
is zero and undo offset equals payload length. Both transaction references are
LSN zero/bytes zero; no native transaction table fixture is thereby qualified.

These table anchors introduce a separate semantic coverage gap: native LFS
envelope flags `4`/`5` are structurally admitted as opaque, even though the
independently decoded mandatory checkpoint records have
flags zero. Pinned
[NTFS-3G `LOG_RECORD_FLAGS`](https://github.com/tuxera/ntfs-3g/blob/78414d93613532fd82f3a82aba5d4a1c32898781/include/ntfs-3g/logfile.h#L334)
names bit `0x4` `LOG_RECORD_ADDING`, introduced in Windows 10, but its surrounding
comment explicitly questions whether the flags describe records or pages.
Pinned Linux defines only multipage bit `0x1` and its
[`find_log_rec`, line 2422](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L2422)
masks that bit without branching on `0x4`. dfir_ntfs observes envelope flags
without using them to select a different payload layout or assembly rule.

This supports structural assembly with opaque bit `0x4`, not
asserting adding/deleting transaction semantics. The implementation
separately exposes `envelope_flag_semantics_supported()` false for that bit, keeps
unknown remaining bits unsupported, retain exact native flags, and independently
qualify single/multipage native table anchors. Page-flag semantic coverage is a
different native field. The native table observations above remain historical
research evidence until the extended public query has its own native gate.

`inspect_ntfs_log_client_record` now borrows complete type-1 record payloads
and validates the 40-byte minimum/declared LCN extent and aligned bounded
redo/undo ranges. Nonempty ranges must follow the structural header; empty
ranges may be at zero or an aligned payload end. Overlap and aliasing are
preserved. Signed target VCN/LCNs, the reserved word, exact operation numbers,
header padding and complete raw bytes remain available. Unknown operations do
not prevent structural inspection, but `operation_semantics_supported()` always
returns false: no redo/undo operation is implemented by this envelope decoder.
LCN access is lazy and constant-time per index; inspection performs no allocation
or I/O. Native fixture bytes are not currently present in the cache, so this
increment does not itself renew any historical native qualification.

The [24-byte `RESTART_TABLE` prefix](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L93)
has entry byte size at 0, slot count at 2, allocated count at 4, six reserved
bytes, free goal at 12, first-free offset at 16 and last-free offset at 20.
Linux calls the count fields `used`/`total`; their operational meaning is clearer
from [`bytes_per_rt`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L380)
and [`check_rstbl`, lines 729–786](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L729).
Native open tables have entry size 40, eight slots and six allocated entries.
Dirty tables have entry size 40, 32 slots and respectively ten/24 allocated.
These yield exact extents `24 + slots * entry_size` of 344 and 1304.

For bounded Rust validation, require entry size at least four before reading its
link, checked total extent within redo bytes and allocated count at most slots.
Each link is allocated sentinel `0xffffffff`, zero, or an aligned entry offset
within that extent. Validate free heads by the same rule. Traverse at most the
slot count, detect cycles and allocated entries in the free chain, and check
first/last consistency; never copy Linux's unbounded linked walk literally.
Retain raw count/reserved/free-goal values rather than inventing meaning for
unqualified flags. Keep slot provenance and distinguish allocated entries from
free entries before decoding type-specific fields. Apply independent slot,
byte, work and findings ceilings to future complete table reports.

`inspect_ntfs_log_restart_table` now implements these generic count/link checks
for source-bound redo dumps of operations 29, 31 and 32. Names operation 30
remains a separate unsupported array profile. Validation borrows the complete
redo slice, charges the header and every slot/free-chain visit, checks cancellation
and enforces independent bytes/entries/work ceilings without heap allocation.
The allocated sentinel count must equal the header count. The terminating free
chain must have exactly the remaining slot count and the declared tail; bounded
traversal detects cycles and rejects allocated chain members. A zero-capacity
structural table may have zero allocated entries and zero heads; no native
empty-table qualification follows from this generic admission.

Raw prefix/reserved/free-goal/trailing bytes remain available. Lazy slot views
expose raw bytes, offsets, links and allocation state; allocated type-specific
fields are exposed separately by the source-owned loader below. Reference-length
correlation is separately observed by the
source-owned loader below. Safety-critical
LCN and table-slot access derives bounds from private immutable source bytes,
so changing public observation fields cannot forge framing or cause an
out-of-range slice. Dump admission likewise reads the original raw operation,
not a caller-modified public operation observation.

### Implemented source-owned checkpoint dump loader

`inspect_logfile_checkpoint_dumps` assembles the checkpoint internally from one
`Arc<dyn ReadAt>` and explicit restart-copy query, then obtains all four references
from its immutable payload. Every nonzero-byte reference is queried from that
same source/copy. Zero-byte references retain their raw LSN without a read;
nonzero-byte references with zero LSN are invalid. Each loaded envelope must
carry the expected redo operation 29/30/31/32. The independently validated
restart context and protected selected restart bytes must equal the checkpoint's
original context, or loading stops with a stale-plan error. The immutable-source
caller contract remains necessary: equal lengths and repeated restart bytes
cannot detect every concurrent same-length payload write.

The owned detailed report retains the checkpoint, all original references and
prior/failed dump records. `references_available()` distinguishes decoded
references, including empty references, from zero placeholders when checkpoint
decoding fails. The report exposes the original stopping error and independent
final cancellation/source-length failure. Reference byte counts are compared
with bounded redo lengths as explicit match observations; a mismatch does not
fabricate a universal corruption rule. Operations 29/31/32 additionally undergo
generic table link/count validation. Operation 30 preserves opaque names bytes
without claiming array-body validation.

Aggregate ceilings include all queries, two retained restart buffers per query,
candidate pages, allocated client payload bytes and work. Work includes the query
step, every repeated restart inspection, record assembly and generic-table scan,
including failed scans. Per-query limits are clamped to the remaining aggregate
budget before reads/allocations; restart work is subtracted before admitting
record work. Reports keep leased record buffers until dropped. No recovery copy
is overlaid, no cross-table identity or replay semantics are validated and no
active-window, transaction-analysis or replay readiness is implied.

Client payload version, not LFS version, selects type-specific layouts. Pinned
[Linux line 4125](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L4125)
uses open-entry size 44 for client major zero and 40 otherwise; only observed
client version 1.0 is currently admitted. Dirty entries have a 32-byte prefix
followed by LCNs; require their declared count to fit the actual entry size.
Transaction entries are 40 bytes but still need independent native qualification.
Do not dereference serialized open-entry pointer bytes; preserve them opaquely.

Borrowed typed entry methods on `NtfsLogCheckpointDumpReport` now expose allocated
slots only after that dump's generic table validation and an independently
decoded immutable client-version-1.0 checkpoint. They do not accept caller-built
table views or mutable version observations. Absent zero-byte tables, free slots
and out-of-range indices return no typed entry; nonempty unloaded/unvalidated
tables and undersized allocated bodies return explicit errors. Earlier validated
tables remain inspectable when a later dump failed.

`open_attribute_entry` checks a 40-byte prefix and exposes index-buffer bytes,
attribute type, FILE reference and open-record LSN. Bytes 12–15 and serialized
pointer bytes 32–39 remain opaque, and all slot tails are retained.
`dirty_page_entry` checks its 32-byte prefix and checked `32 + 8 * LCN_count`
extent, exposing signed VCN/LCNs and preserving tails. Lazy LCN access uses
private original bounds even if public count observations are edited.
`transaction_entry` checks 40 bytes, retains the raw state, reserved bytes,
first/previous/undo-next LSNs and undo counts, and preserves any tail. Original
state codes zero through three have local code coverage; unknown states remain
available with `state_semantics_supported()` false. This does not validate
transaction chains or authorize undo. Cross-table identities, allocation ownership,
chronology and replay semantics remain separate outstanding requirements.

`dirty_page_open_attribute(index)` adds a source-owned structural join between
one allocated dirty slot and an allocated open-attribute slot from the same
checkpoint report. The target is the original dirty slot's `u32` at offset four,
interpreted as a byte offset into the open table, as in pinned
[Linux line 4824](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L4824).
It must be at least 24, aligned relative to the original open-table slot stride,
within capacity and allocated; the open body must have its admitted 40-byte
prefix. Zero points into the table header and is not assigned a guessed null
meaning. Missing/unvalidated open tables and free/misaligned/out-of-range targets
are explicit invalid-data outcomes. Missing dirty tables, free dirty slots and
out-of-range requested dirty indices return no join. The returned borrowed view
retains both slots and the exact target index/offset through read-only methods.
No caller-provided mutable entry fields participate. This does not establish
current FILE identity, stream/attribute existence, LCN ownership, chronology or
replay safety; those remain necessary later joins and qualification gates.

The borrowed entry decoders consume allocated slots from a validated generic dump
and the internally decoded client version. The pinned version-1 layouts are:

| Dump | Minimum slot | Fields after the allocation link |
| --- | --- | --- |
| Open attributes | 40 bytes | index bytes at 4, attribute type at 8, opaque bytes 12–15, raw FILE reference at 16, open-record LSN at 24, opaque runtime pointer bytes 32–39 |
| Dirty pages | 32 bytes plus eight per declared LCN | target open-attribute offset at 4, transfer bytes at 8, LCN count at 12, VCN at 16, oldest LSN at 24, LCN array at 32 |
| Transactions | 40 bytes | state byte at 4, reserved bytes 5–7, first/previous/undo-next LSNs at 8/16/24, undo record count at 32, undo bytes at 36 |

Dirty-page LCN arithmetic must be checked against the actual slot before exposing
lazy elements. Free-entry bodies and unknown tails remain raw. Linux's open-entry
name flags are runtime bookkeeping and must not be interpreted as validated
serialized flags. Transaction state values 0–3 can be named as observations;
unknown values retain their raw byte and unsupported semantics. Zero LSNs,
unknown attribute types and serialized LCN markers do not establish corruption
or replay readiness by themselves. Cross-table target offsets require a separate
join to an exact allocated open-attribute slot in the same checkpoint context;
that join still does not prove FILE ownership or allocation coverage.

Attribute names are a separate variable array, not a `RESTART_TABLE`.
There is a material source disagreement: Linux's name walk advances by
`4 + name_bytes`, whereas pinned
[dfir_ntfs `AttributeNameEntry`, lines 1864–1897](https://github.com/msuhanov/dfir_ntfs/blob/ec3ae0884048ade106c91a68dab7c9fb3af393bf/dfir_ntfs/LogFile.py#L1864)
includes a trailing two-byte NUL. The native 46-byte dump begins with an
eight-byte UTF-16 `$I30` name plus a terminating NUL before the next entry.
Resolve the complete array and terminator rules against these native bytes
before publishing a names iterator; keep arbitrary native UTF-16 units lossless.
Cross-table offsets, FILE identities, allocation coverage, table LSN ordering and
transaction recovery are subsequent checks, not consequences of structural dumps.

Pinned [Linux restart selection, lines 3842–3852](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L3842)
chooses the valid candidate with the larger numeric current LSN. Its
[`log_read_rst`, lines 1203–1308](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L1203)
provides valid-copy fallback. The candidate API retains rejected-copy
errors, requires compatible version/geometry and distinguishes equal-LSN conflicting
contexts. Never merge client identities across copies: the selected context's
client index and sequence govern record ownership. A malformed USA candidate
may permit fallback; cancellation, source changes and exhausted resources must
not silently become healthy fallback. I/O failure needs an explicit partial
coverage outcome rather than an unqualified complete selection claim.

Neither pinned implementation supplies a general sequence-counter-rollover
ordering algorithm. Numeric selection must document that qualification limit;
do not invent a modular-distance rule or claim a small isolated LSN proves a
recent rollover. Include different client sequences, equal-LSN contradictory
areas, one/two torn copies and mixed versions in selection tests.

For 2.0 fast-copy preprocessing, follow
[Linux `last_log_lsn`, lines 1629–1778](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c#L1629):
pair slots at pages 2–17 with pages 18–33, compute each candidate's `base_lsn`
using target offset and conditional next-record bounds, and rank the pair by that
value. A candidate chain additionally requires a common generation, consecutive
target offsets, increasing base LSNs and admitted transfer count/position
continuity. It is bounded by the 16 paired positions. These checks precede the
normal forward discovery state machine and its torn-transfer lookahead; ranking
alone never authorizes overlay installation.

Pinned [dfir_ntfs `apply_fast_pages`, lines 1223–1252](https://github.com/msuhanov/dfir_ntfs/blob/ec3ae0884048ade106c91a68dab7c9fb3af393bf/dfir_ntfs/LogFile.py#L1223)
sorts newer fast pages by header LSN and writes their targets. That forensic
preprocessing is useful independent comparison evidence but does not establish
the Linux recovery state machine's generation/transfer conditions. Implement an
immutable page overlay with exact source-slot/target provenance, keeping the
original native stream untouched. Native crash pairs spanning restart changes,
fast transfers and physical wrap are still required before complete active-window
or replay claims.

Restart-copy selection and tail discovery must be separate from exact queries.
The strict query requires matching supported restart areas; explicit-copy queries
retain their caller-selected context without choosing authority. Linux chooses
between valid restart copies using their current LSN; changing that contract
requires tests for divergent generations, torn copies and native crash states.
Reject incompatible geometry/client identities before comparing candidates.

For a selected context, derive the candidate endpoint from current LSN plus
last-LSN payload length, including circular continuation and whether the endpoint
page can be reused. Derive the lower bound from the minimum nonzero oldest LSN
of the validated in-use clients, seeded by current LSN. A pseudo lower bound is
not permission to scan stale pages as live records.

Then implement a bounded forward discovery state machine following Linux
`last_log_lsn` (lines 1600–2239): current physical offset, expected generation,
last accepted LSN, transfer page count/position, reuse mode and tail candidates.
An ordinary page must match the expected generation or the prior accepted LSN
where the algorithm permits reuse, and must satisfy transfer continuity. At
transfer boundaries a 1.1 tail candidate must target this ordinary offset.
If both tails target it, last-ended LSN comparison is only a candidate ranking;
the winner still needs expected-generation and accepted-endpoint checks.
No tail may roll the accepted endpoint backward. A newer admissible tail can
provide an immutable read overlay for the target page; never repair the source
while discovering it. Torn-transfer lookahead and termination must be modeled
explicitly before claiming complete discovery.

The active-record iterator then starts from a validated checkpoint/client
restart anchor, uses exact queries and checked successors, and ends at the
discovered endpoint. Previous/undo links require exact client identity and
bounded visited-LSN tracking. An older-generation page, missing segment, cycle,
unsupported operation or budget exhaustion prevents complete analysis. The
replay overlay and transaction tables remain subsequent requirements.

## Required tests and native evidence

Synthetic tests must cover round-trip LSN conversion, exact power-of-two file
sizes, invalid sequence bits, pseudo/zero LSNs, header/tail addresses, one and
multiple circular continuations, exact page-end payloads, alignment padding,
short headers, mismatched `this_lsn`, oversized payloads, absent multipage flags,
premature completed pages, missing final completion evidence, stale generations,
generation overflow, client mismatch, cycles, cancellation and every resource
ceiling. Test endpoint arithmetic separately from successor arithmetic.

Tail tests need both tails targeting one page; equal and different completion
LSNs; newer tail with wrong generation; tail older than accepted endpoint;
target mismatch; valid tail over torn ordinary USA; torn tail over valid ordinary
page; reused transfer end; inconsistent page positions/counts; and wrap during a
transfer. Assertions must prove which page supplies each assembled byte.

The existing clean offline Windows fixture proves framing and stream selection
only. Acquire independent **foreign dirty** before/after pairs on dedicated
disposable data disks: capture while ordinary writes, directory/index updates,
ADS changes and allocation changes are active, preserving the VM's crash point
without a clean dismount. Never corrupt a clean fixture and label it native
dirty evidence. Snapshot the data disk consistently while VM execution is
paused/stopped, record exact workload and acquisition barrier, and preserve the
pre-recovery image. Run native Windows recovery on a separate clone, retain
post-recovery bytes and read-only check results, and compare namespace, stream
bytes, allocation and metadata through independent readers. Include an actual
log-wrap workload and torn-write cases with a recorded fault mechanism.

Unknowns requiring evidence are the observed 1.1 tail flags 3 interpretation,
restart divergence selection, client entry/version differences, record operation
allowlists, checkpoint table formats and sequence rollover. The initial exact
record query may expose opaque payloads while these remain unresolved, but must
not advertise recovery readiness or authorize durable mutation.
