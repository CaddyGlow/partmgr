# NTFS DATA and attribute-list reads

The DATA/ADS and attribute-list reader is integrated in `partmgr::fs_ntfs`.
Integrated checks qualify this source separately from the isolated native receipt.
This is not full NTFS support. USN framing remains a separate evidence source.

`NtfsVolume::stream_identity(number, resources)` obtains the allocated base-record
identity for the explicit profile. `data_streams(owner, limits, resources)` returns
retained bounded exactUTF16 stream descriptors; `open_stream(owner, name, limits,
resources)` returns a reusable deferred `FileRead`. Empty name identifies ordinary
unnamed DATA; named DATA may belong to files or directories. Identity remains the
owning object, so extraction must bind the exact stream name separately. Deferred
reads retain the indexed map, check cancellation and source length, and do not
reopen or rescan MFT records. Caller-established stability remains required; unchanged
length and immutable capabilities do not create a snapshot.

The resolver loads resident or bounded ordinary nonresident ATTRIBUTE_LIST values
and binds entries to exact record/sequence, instance, type, native name and lowest
VCN. Extensions must point back to the same base reference. Every loaded attribute
must be listed, except the base list may omit itself. Duplicate targets, recursive
extension lists, missing instances, stale sequences and contradictory references
fail. Split nonresident DATA must begin atVCN0 and continue without gaps or overlaps;
aggregate runs, virtual allocation, initialized prefix and within-stream physical
ownership are checked. Sparse holes and uninitialized allocation remain distinct.
Continuation size fields are retained rather than used as whole-stream sizes; each
segment's LCN deltas start from its own zero origin. All working/retained allocations
consume Resources, alongside record/extension/list/attribute/run/work ceilings.

`native_attributes` retains exact fixed-up attribute bytes, base owner, physical
record/sequence, record offset, type, instance, flags and name. It includes the base
ATTRIBUTE_LIST and otherwise undecoded metadata. Typed native SI and FILE_NAME views
retain creation/modification/MFT-change/access timestamps independently, preserving
raw48/72-byteSI values and security index when present. No core metadata fields or
security semantics are invented. Native extension resident reserved byte23 was
observed as0xd6 in independent ntfs-3g output: the explicit profile preserves it as
opaque, while the existing strict base-record profile remains unchanged.

Remaining requirements are explicit: MFT itself depending on attribute-list
bootstrap, recursive/split ATTRIBUTE_LIST values, complete native name collation,
compressed/encrypted content and metadata profiles, expanded tree/copy streams,
resolved extension whole-volume ownership audit, all system streams, full security
integration, VSS/persistent snapshots and recoverable native NTFS editing. The old
reader/tree/audit gates are retained; successful stream reads do not authorize them
to claim complete capture or clean allocation ownership.

## Primary sources

- [Microsoft ATTRIBUTE_RECORD_HEADER](https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header): native3.0/3.1 resident/nonresident headers and continuation size-field validity.
- [Microsoft ATTRIBUTE_LIST_ENTRY](https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-list-entry): aligned bounded references/names/VCNs.
- [NTFS3G native attribute-list implementation](https://github.com/tuxera/ntfs-3g/blob/edge/ntfsprogs/ntfsinfo.c): entry instance handling and independently generated native fixture inspection.
- [Microsoft MS-FSCC Time](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a69cc039-d288-4673-9598-772b6083f8bf): native signed100ns ticks since1601UTC.

Browsed2026-10-08. The Microsoft list page labels the final16-bit field reserved;
NTFS3G's native instance interpretation is checked against its actual produced
records rather than guessed solely from that incomplete field label.

## Qualification

Portable reader tests:13pass and2explicitnative gates ignored by ordinary runs.
Added fixtures independently assemble resident ADS, resident lists/extensions,
131089-byte two-extension DATA, stale/bad references, missing instances, VCN defects,
physical overlap, aggregate limits, cancellation and provenance/timestamp retention.
128small reads are counted exactly128payload reads; EOF adds none. All reservations
refund. Existing NTFS tree/audit focused regressions pass separately.

Native checkpoint `/data/cache/partmgr-ntfs-stream-native-20261008-v3/verification.json`
contains7archived source bindings, fixed executable,202artifact hashes and3fatal
controls. The gate runs only with `--ignored`; required tools/evidence missing fail,
and existing evidence destinations are preserved. It creates a64MiB image using
NTFS3G2026.9.18, writes an unnamed stream plus20ADS, actually produces a nonresident
1248-byte ATTRIBUTE_LIST and extension FILE records, and reads every exact payload
through the draft decoder, ntfscat and independent SleuthKit4.14.0icat. Largest ADS
is131089bytes. An independent Python verifier regenerates all21models, checks source
and artifact hashes, and tests missing tools/evidence and existing destination.
The source-end guard matches, image bytes remain unchanged and all leases refund.
These Linux-native tools do not prove Windows VSS, restore, replay or ACL behavior.
Failedv1 and successfulv2 evidence are retained as historical checkpoints.
