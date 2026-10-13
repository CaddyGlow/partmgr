# Native NTFS `$LogFile` inspection and recovery design

This is the next N2 dependency in
[the maintenance plan](filesystem-write-maintenance-plan.md), after resolved
ownership accounting. Nothing described here is an implemented replay engine.
The existing audit excludes journal and hibernation assurance; the USN decoder
and `$J` extraction describe a different native stream and cannot establish
`$LogFile` transaction state.

## Pinned implementation references

These are primary implementation sources, not a claim of Microsoft format
specification or Windows qualification. They were fetched and hashed on
2026-10-10. Local research copies are under
`/data/cache/partmgr-maintenance-specs/ntfs-logfile/`.

| Source | Immutable revision | SHA-256 of downloaded source |
| --- | --- | --- |
| [Linux `fs/ntfs3/fslog.c`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c) | Linux v6.12; tag object `06090c9b622a7e1f797e775db4c035e0d779b76e`, peeled commit `adc218676eef25575469234709c2d87185ca223a` | `5d0f8866ef76ddfcda396916112be0e0382d2ee8ecffec21b97775c2a1c19264` |
| [NTFS-3G `include/ntfs-3g/logfile.h`](https://github.com/tuxera/ntfs-3g/blob/78414d93613532fd82f3a82aba5d4a1c32898781/include/ntfs-3g/logfile.h) | 2022.10.3, `78414d93613532fd82f3a82aba5d4a1c32898781` | `55a459c5e0cc2e9c392e98fe3e0d412c0677532783f183780d467018a3582290` |
| [NTFS-3G `libntfs-3g/logfile.c`](https://github.com/tuxera/ntfs-3g/blob/78414d93613532fd82f3a82aba5d4a1c32898781/libntfs-3g/logfile.c) | Same revision | `fc6ac1af5f6f7ffe924ba150f0350173b85b7a787a7e0cbd002f6f01237be29f` |
| [dfir_ntfs `LogFile.py`](https://github.com/msuhanov/dfir_ntfs/blob/ec3ae0884048ade106c91a68dab7c9fb3af393bf/dfir_ntfs/LogFile.py) | `ec3ae0884048ade106c91a68dab7c9fb3af393bf` | `e3bb9d488c5fed46c28fc44c486a45df100808b0d09cce9d3ab78b9bdf347b5e` |

The sources disagree in breadth: NTFS-3G's header describes the historical 1.1
profile, while its checker explicitly accepts 1.1 and 2.0; Linux's replay switch
lists 1.0, 1.1, 2.0. That is evidence for explicit version dispatch, not permission
to treat these layouts as interchangeable. Linux also uses distinct ordinary
record-region starts for versions below 2 and versions 2+. [Sources: Linux
`log_init_pg_hdr` and replay version switch](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c),
[NTFS-3G restart checker](https://github.com/tuxera/ntfs-3g/blob/78414d93613532fd82f3a82aba5d4a1c32898781/libntfs-3g/logfile.c).

## Implemented: bounded read-only restart inspection

`fs_ntfs_logfile::inspect_logfile` observes the two restart copies from a bounded
read-only stream. `inspect_ntfs_logfile` resolves record 2's exact unnamed DATA
through the shared native map engine, requires ordinary initialized content, and
retains its base identity and observed volume flags. Scratch is reserved before
reads; the APIs do not open a writable device or clear a marker. The restart inspector covers headers, areas and their single client. The separate
physical-page inventory below adds local page framing; record payloads and
transaction analysis remain unimplemented.

The restart allowlist is deliberately exact: versions 1.1 and 2.0, 512-byte transfer
sectors, and 4096-byte system/log pages. The physical inventory dispatches both
versions' distinct recovery-copy topology. Exact record queries admit both
versions with their corresponding ordinary-region starts. The strict API requires
fully matching restart areas; the explicit-context API identifies one
independently validated source-bound copy without choosing an authoritative
newest restart. No query applies fast copies. Neither API establishes recovery semantics.
Broader geometry/version support needs its own fixture and topology evidence.
Neither an unsupported version nor a zero/`0xff` page becomes a clean journal.
`CHKD` signatures are observed recovery-tool state requiring separate support.

Decode integers explicitly little-endian; do not transmute these source structs.
The following field map describes the implemented restart parser. Offsets are hexadecimal.
Header and area fields below are independently recorded in NTFS-3G's
[layout definitions](https://github.com/tuxera/ntfs-3g/blob/78414d93613532fd82f3a82aba5d4a1c32898781/include/ntfs-3g/logfile.h).

| Structure | Field offsets and widths |
| --- | --- |
| Restart header | `00` signature4; `04` USA offset2; `06` USA count2; `08` chkdsk LSN8; `10` system-page bytes4; `14` log-page bytes4; `18` restart-area offset2; `1a` minor2; `1c` major2 |
| Restart area, relative to its offset | `00` current LSN8; `08` client count2; `0a` free-head2; `0c` in-use-head2; `0e` flags2; `10` sequence-bit count4; `14` area length2; `16` client-array offset2; `18` usable file bytes8; `20` last-LSN data bytes4; `24` record-header bytes2; `26` page-data offset2; `28` open count4 |
| Historical client entry, 160 bytes | `00` oldest LSN8; `08` restart LSN8; `10` previous2; `12` next2; `14` sequence 2; `1c` name bytes4; `20` UTF16LE name, at most 128 bytes |

The client layouts differ between the pinned sources: NTFS-3G declares 64 UTF16
units, making its entry 160 bytes; Linux declares 32 units and asserts 96 bytes.
The implemented historical 1.1 and observed 2.0 restart profiles require one 160-byte slot for a present
client and accepts at most one client; it does not infer a multi-client stride
from Linux's layout. Both retain the name at offset `0x20`. This disagreement is an
explicit profile constraint rather than a universal 96-byte assertion.

The genuine Windows workload power-cut fixture at
`/data/cache/partmgr-ntfs-windows-dirty-logfile-20261010-v1/` independently
contains two version 2.0 restarts with area length 224 and client offset 64,
retaining the complete 160-byte client slot. Both use USA offset 30/count 9,
restart area offset 48, file bytes 2686976, sequence bits 45, record header
48 and page data offset 64. Their different current LSNs (4753128 and 4839042)
remain explicit disagreement; this implementation does not choose the newer
copy. The acquisition receipt and preserved stream SHA-256
`d027c26addbb038c896f493868d9da85a0b7a883933429bbcad11109496ec912`
identify the observed bytes, not a recovery result.

The physical inventory's version dispatch accounts for the
2.0 ordinary region starting at page 34, following 32 fast-copy pages. Unlike a
1.1 tail, a 2.0 fast copy retains an LSN at offset `0x08` and a separate target
file offset at `0x3c`. Pinned Linux `log_init_pg_hdr` and `hdr_file_off`, and
dfir_ntfs `get_wrapped_log_record_page_number` and `get_file_offset_2x`, agree on
these distinctions. A version-2 restart must never feed the existing page-4
ordinary start or 1.1 tail interpretation. All 32 fast-copy slots are observed
as `FastCopy { index }`; their raw `0x08` LSN and separate `fast_copy_target`
are retained. Fast-copy USA arrays must end by byte 60. A framed target must be
4096-byte aligned, at or beyond page 34 and below the declared usable end.
An invalid target retains its raw bytes and locally framed header with the
original invalid-data error, while physical enumeration continues.
`fast_copy_target_checked` separately records destination validation; a framed
header alone does not establish destination bounds. No fast copy
is selected or applied. Conditional next-record bounds use the LSN interpretation
for both ordinary pages and fast copies, keeping 1.1 tails separate.

The two restart candidates are at 0 and 4096. Each is validated independently;
raw bytes, individual errors and mismatches are retained. Checked sums/products
precede slicing. The parser requires USA count 9, even USA offset at least `0x1e`,
USA placement before the restart area, matching transfer trailers and successful
fixups before interpreting protected bytes. Area/client ranges must fit, with
critical prefixes before the first transfer trailer. Client heads must describe
the admitted empty/single-client state; malformed links and unsupported client
identities are rejected.
Use the encoded client-array offset; do not assume all historical areas have the
same prefix length. The sequence-bit consistency rule is
`67 - bit_length(usable_file_bytes)`; reject invalid shifts and usable sizes beyond
the actual stream. These checks follow the pinned
[NTFS-3G restart-area/client checks](https://github.com/tuxera/ntfs-3g/blob/78414d93613532fd82f3a82aba5d4a1c32898781/libntfs-3g/logfile.c),
with additional conservative bounds proposed here.

## Implemented: bounded physical-page inventory

`fs_ntfs_logfile::inspect_logfile_pages` requires both admitted restart areas to
agree on version, usable file size and page-data offset. It observes each physical slot
from 8192 to that shared end, distinguishing 1.1 tail slots at 8192/12288 and
ordinary slots beginning at 16384, or 2.0's 32 fast-copy slots followed by
ordinary slots beginning at 139264. `NtfsLogPageLimits` independently bounds
candidate pages, retained raw bytes and work.
`inspect_ntfs_logfile_pages` selects the exact ordinary initialized record 2
stream through the same native selection helper and returns its scoped owner and
volume flags with the complete physical-page report. Independently opened volumes
have distinct source scopes; qualification compares native record number and
sequence while preserving that distinction. The report retains malformed,
erased and unsupported candidates and continues past local format errors; I/O,
cancellation, source guards and budgets stop it with prior evidence retained.
It does not select an authoritative tail or infer an active transaction chain
by sorting unsigned LSNs. The pinned Linux structs give this record framing:
`RCRD`, USA at 04/06, page metadata at 10, count/position at 14/16,
next-record offset at 18, last-ended LSN at 20. Version 2 adds distinct page-location
semantics, including a field at 3c. [Linux framing definitions](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/ntfs3/fslog.c).

The physical-page implementation requires a structural USA
minimum of 40 bytes (the complete fixed page header), count 9, an even offset and
array end no later than the admitted data offset or byte 510. Data offset and a
meaningful next-record offset are eight-byte aligned; the latter is bounded by
page size. Preserve count/position with the admitted range
`1 <= position <= count`; this does not establish transfer succession.
Linux's `base_lsn` consults next-record offset conditionally when the end-of-record
flag and its LSN comparison apply. A page with no completed record can have an
unused offset; do not impose a completed-record boundary on every physical page.
`next_record_offset_checked` is true only for ordinary pages with the end bit
and raw header LSN no greater than last-ended LSN, following the source's local
use condition. False means the raw offset is unused/unvalidated, not a validated
payload range. This condition does not establish circular LSN chronology.
`scan_complete` means all declared physical slots were observed and final guards
passed; it does not mean all pages have valid or supported headers. Each
observation separately exposes `framing_valid` and `semantics_supported`.
`active_window_complete` and `transaction_analysis_complete` always return false.

Physical tail copies require separate header interpretation: offset `0x08` is a
file byte offset for a 1.1 tail, rather than the ordinary page's LSN. The newly
pinned [dfir_ntfs parser](https://github.com/msuhanov/dfir_ntfs/blob/ec3ae0884048ade106c91a68dab7c9fb3af393bf/dfir_ntfs/LogFile.py)
explicitly calls page bit `0x2` unknown and associates it with client-restart pages
in 2+ logs. It distinguishes that bit from record flags at another structural
level. Preserve raw flags 3 observed in a tail; neither assign bit 2 a guessed
universal meaning nor infer a 2.0 restart version from it. Unknown page-bit
semantics remain visible independently of successfully checked framing: flags 3
retain framed fields with an unsupported-semantics error. A tail's raw target
offset is preserved without validating target provenance or selecting a copy.

## Next: record assembly and active-window analysis (unimplemented)

The pinned source describes an individual record header of 48 bytes:
three 8-byte LSNs at `00/08/10`, payload length at `18`, client ID at `1c`,
type at `20`, transaction ID at `24`, and flags at `28`. This record structure
is not decoded by the physical-page inventory.

Validate record bounds before exposing any borrowed payload. Preserve
unknown flags and operation codes as unsupported observations. A multipage
record is explicitly incomplete until a separately bounded assembly state
machine establishes page order, generation, continuation length and ownership.
No first-stage result claims that every retained page belongs to the active log.
The clean flag is a native observation only; it is insufficient to authorize
mutation or establish complete recovery.

## Resources, reports and tests

The implemented restart inspector bounds bytes, work and retained copy evidence.
For the next record-assembly phase, provide independent ceilings for clients,
headers, assembled bytes, work and findings. Charge page scans, client walks and every
record before processing; check cancellation between I/O and publication. Lease
retained findings and release scratch on every failure. For future record
assembly, a detailed failure must keep validated prior evidence and the original error, mark coverage incomplete, and never offer replay
readiness. The report distinguishes raw header observations,
version support, restart-copy validation, page framing coverage and transaction
analysis coverage. The first implementation always reports transaction analysis
as unimplemented.

Host restart fixtures cover framing, USA, geometry, single-client links, copy
disagreement, unsupported states and resource failures. Physical-page fixtures
additionally cover tail roles, local offset checks and page-resource failures. Future record fixtures must cover truncated headers and
multipage boundaries. Include late cancellation, backend I/O failure, budget exhaustion and scratch
refund checks. An all-zero/all-`0xff` freshly initialized log is a distinct state,
not fabricated empty transactions.

## Scoped Windows evidence

The Windows-authored offline fixture first passed a restart-only gate. This
historical receipt binds the earlier source revision and remains scoped to that
restart-only implementation:

`/data/cache/partmgr-ntfs-windows-logfile-20261010-v1/inspection-qualification.json`,
SHA-256 `49cbbbe0d826e8a3eb21ceef16c7276c99771ef9e7a8c642265a665da0aa6596`.
That gate retained exact stream/volume hashes, restart bytes, source/binary
bindings and independent acquisition observations; missing inputs and reused
evidence destinations failed as required. Both raw offline headers are 1.1 with
4096-byte pages, USA offset 30/count 9 and matching restart areas with clean flag 2.
The system-stream adapter selected record 2, sequence 2, with volume flags 128
(dirty bit clear). Mounted Windows `fsutil` reported log version 2.0, so this
receipt qualifies the observed offline 1.1 bytes and does not qualify 2.0 parsing.
`transaction_analysis_complete` remains false. This is clean restart inspection
and system-stream selection evidence only, with no recovery or writer claim.

The final current-source volume/page gate passed with receipt
`/data/cache/partmgr-ntfs-windows-logfile-20261010-v1/volume-pages-v3-qualification.json`,
SHA-256 `c313f1bc3afb08f1f44321cea99c7ef02323fdfb5bbe94d26bfe79e98c124ee2`.
The full 654-candidate inventory matched between the direct journal stream and
record 2 selected from the volume, and independently matched the Python oracle's
protected page hashes and raw header fields: two tail copies, 54 ordinary RCRD
pages, and 598 all-`0xff` pages. Both tails retained flags 3 as locally framed
headers with unsupported semantics. Native record 2/sequence 2 and volume flags 128
matched; separately opened volumes retained distinct source scopes. Seven
negative controls for missing stream, volume, acquisition receipt, oracle,
source root, evidence destination, and reused destination all failed.
Neither scan completion nor this exact physical equality establishes active
pages, individual record payloads, transaction analysis, recovery or writing.

Earlier `pages-qualification.json` (SHA-256
`3b1bd2c84d18a8a567157fa127da92a16632806fbece494f92a50c56d1f40b98`)
is historical direct-stream page evidence bound to its earlier source revision.
The first volume attempt's incorrect identity equality assertion is retained;
its correction compares native identity/sequence while preserving independent
source scopes. The second attempt's compiled-source mismatch is also retained.
The final v3 gate was rebuilt against stable source and passed.

The physical-page gate additionally requires an external TSV inventory through
`PARTMGR_NTFS_LOGFILE_PAGE_ORACLE`. Generate a new artifact from the exact stream
with the independent raw-field oracle:

```sh
python3 integration/maintenance/logfile-page-oracle.py \
  /data/cache/partmgr-ntfs-windows-logfile-20261010-v1/logfile.bin \
  /data/cache/partmgr-ntfs-windows-logfile-20261010-v1/logfile-pages.tsv
```

The output path must not already exist. The TSV binds the complete stream hash
and every protected page hash, then records physical offset, page kind and raw
header fields. Its USA verification restores trailer bytes independently of the
Rust parser. Set `PARTMGR_NTFS_LOGFILE_PAGE_ORACLE` to that absolute TSV path when
running the explicitly enabled native gate alongside its existing stream,
volume, acquisition-receipt, source-root and new evidence-directory inputs.
This inventory does not select active pages, choose a tail copy or validate LSN
ordering; the page-framing receipt above states that limited scope.

Before recovery qualification, obtain additional Windows-authored images with saved Windows
build, sector/cluster geometry, observed log version, exact raw image and stream
hashes, and independent restart/page inventories. Require clean dismount,
controlled interrupted metadata operations, genuinely torn page, conflicting
restart copies, circular wrap, committed and aborted transactions, multipage
records, extension-record metadata and bitmap changes. Collect both 1.1 and 2.0
fixtures; never assume a Windows release implies one version. Preserve the
unmodified pre-recovery image and a separate clone recovered by native Windows;
compare namespace, metadata and full physical allocation afterward. Enabling the
gate without required artifacts must fail. Linux-authored logs and hand-built
fixtures cannot replace this gate.

After inspection, N2 still requires verified active-window/LSN ordering, NTFS
checkpoint tables, redo/undo operation semantics, target-page provenance,
idempotent recovery ordering and flush/failure evidence. Only then can native
transaction planning/publication be designed. A private undo sidecar is not a
substitute for those native requirements.
