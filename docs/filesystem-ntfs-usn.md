# NTFS USN V2/V3 forensic decoding

`partmgr::fs_ntfs_usn` decodes already-framed USN evidence without writing.
The standalone prototype receipt remains historical evidence; integrated checks
qualify the repository version separately.

`decode_record(bytes, Provenance, RecordLimits)` returns a borrowed `UsnRecord`.
`Records::new(bytes, provenance, StreamLimits)` provides bounded sequential decoding;
`next_record(|| cancelled)` checks cancellation before each record and the first EOF
request. It stops permanently on error. Record byte/name limits and whole cursor
byte/record limits are checked before advancement. The parser performs no allocation;
input retention and any collection of returned records remain caller responsibilities.
Integration can use the existing partmgr Resources cancellation token through the
callback and charge any caller-owned input buffers/collections to its memory pool.

Each record retains its exact bytes, caller-supplied evidence label and offset,
native USN, signed timestamp ticks, file and parent identifiers, raw reason/source
flags with separately exposed unknown bits, raw store-local security index, raw
attributes, dynamic name bytes, and opaque extension/trailing bytes. UTF16 code
units are exact; NULs, unpaired surrogates and noncharacters are retained. Display
conversion is a caller policy. V2 references offer an explicitly NTFS-only low48
record/high16 sequence interpretation; V3 references remain opaque128 bytes.
Provenance identity is a label rather than a verified hash or source-stability proof.

A known major2/3 framing layout is required. Compatible minor versions retain any
pre-name extension using the encoded offset. Record length must be8-byte aligned;
name offsets/lengths must be even, outside the fixed prefix and inside the record.
Negative USNs, offset overflow, short prefixes, truncated records and excessive
limits fail with typed errors identifying the source and field position. Reserved
reason/source bits are retained as forensic observations rather than silently
removed or taken as proof that a record is native/authentic. Attribute bits are
preserved without a guessed applicability mask.

The input slice must begin at a known record boundary. Sparse `$J` holes and the
initial8-byte USN in a DeviceIoControl result need explicit extraction/envelope
handling before this decoder; it does not silently scan for plausible headers.
There is no NTFS stream extraction, MFT interpretation beyond the optional V2 ID
split, transaction-log replay, deletion/file recovery, timeline attribution,
rename-pair inference, carving, or journal modification capability in this draft.

## Primary definitions

- [Microsoft MS-FSCC USN_RECORD_V2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d2a2b53e-bf78-4ef3-90c7-21b918fab304): fixed fields, nonnegative native USN, dynamic UTF16 name extent.
- [Microsoft MS-FSCC USN_RECORD_V3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/bb07c6b8-74be-49b5-9723-04f4d9e3e44d):128-bit references and shared trailing fields.
- [Microsoft Win32 V2 remarks](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2):8-byte record alignment, compatible minor additions and dynamic names.
- [Microsoft MS-FSCC Time](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a69cc039-d288-4673-9598-772b6083f8bf): signed64-bit100ns native epoch1601UTC.
- [Microsoft Win32 V4 flag definitions](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v4): shared reason flags including TRANSACTED_CHANGE and client replication source flag. V4 record decoding itself is unsupported.

These sources were browsed2026-10-08. Reason/source masks describe the documented
interpretation set and do not authenticate records or reject unknown future flags.

## Evidence

`tests/fixtures/ntfs_usn_generate.py` independently assembles1024 mixed records from
Microsoft's field offsets with Python struct.pack. `tests/fixtures/ntfs_usn_mixed.bin` is84656 bytes,
SHA256 `e59554456dd4bf7fc03ddd1e46059f4f8d14686cee4ba1520e0c53e57099cad6`.
It is synthetic evidence, not a Windows journal capture. The Rust test reads every
record and independently checks identifiers, offsets, native timestamps, unknown
flags, opaque minor extensions, and exact names. Other tests cover every truncation,
malformed lengths/ranges/versions, field mutations, budgets, cancellation, terminal
errors, overflow and explicit refusal to skip holes/envelopes.

See `/data/cache/partmgr-forensics-usn-workspace/evidence/receipt.json` for fixed source, fixture, executable and command-log
hashes plus results. This evidence qualifies a standalone framing decoder only.
