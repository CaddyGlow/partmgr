# Compressed owned editing protocol

The default editor and recovery entry points remain strict NONE/ZERO consumers.
Compressed editing requires an additive explicit profile for RTIME or ZLIB,
including the reader's encoded-node, decoded-node, aggregate byte and work caps.
This profile has portable modeled-interruption tests and independent completed-image native evidence. It does not establish physical power-loss safety.

The current checkpoint implements shared borrowed codec scanning, physical node
certificate resolution, bounded mapping reads and private versioned intent
serialization/profile matching. Strict plans still author version 1, and strict
recovery rejects authenticated version 2 with zero target and journal writes.
`Jffs2Editor::open_compressed` and `recover_compressed` take explicit
`Jffs2EditCompression`; opted-in plans bind the selected codec and decoder limits
into version 2. Portable complete transactions cover both codecs/endians through
shared-inode range replacement, truncation, fresh inode replacement, native-byte
creation and live GC, then immutable audit/payload/hardlink reopening. Mutation and recovery interruption matrices cover both codecs and endians with all four target/journal volatile retention combinations. Independent native completed-image evidence is recorded below. Equal virtual addresses in different registries are
independently tested to resolve to different physical payloads.

An authenticated versioned external intent must bind the codec choice and every
decoder limit. Strict recovery must reject that version before target or journal
writes. Opt-in recovery must require the exact caller profile, validate all
records and replay compatibility, and validate the complete reconstructed
baseline before mutation. Existing PREPARED, COPIED and COMPLETE ordering remains:
replacement records are CRC-valid, read back and flushed before COPIED becomes
durable; only durable COPIED permits erasing the victim. NOR replay requires
`(observed & expected) == expected`. COMPLETE recovery checks the actual image
digest and namespace without writes.

The `JFF2TX02` header retains the 512-byte framing, SHA-256 at byte 480,
two alternating header slots, and body at byte 1024. Its authenticated extension
uses previously reserved bytes:

| Offset | Width | Meaning |
| --- | --- | --- |
| 236 | 4 | Authoring codec, native RTIME 2 or ZLIB 6 |
| 240 | 4 | Maximum encoded bytes per node |
| 244 | 4 | Maximum decoded bytes per node |
| 248 | 8 | Aggregate encoded scan bytes |
| 256 | 8 | Aggregate decoded scan bytes |
| 264 | 8 | Decoder byte-work limit |
| 272 | 208 | Required zero |

All integers remain little endian independently of the declared node endian.
Both valid header slots must agree on the version and extension in addition to
their existing immutable fields. An unsupported version, mixed-version pair,
unknown codec, nonzero reserved bytes, mismatched caller limits or invalid bounds
must fail before mutation. The journal stores exact emitted encoded bytes; replay
does not recompress nodes and cannot change output with a codec library upgrade.

The borrowed FlashStorage decoder must share the immutable reader's bounded
codec implementation without implementing ReadAt on mutable storage. A compressed
fragment locator identifies a registry entry and decoded offset. Registry indexes
depend on scan order and therefore cannot establish content equality across two
views. Content proofs must resolve each locator to its physical node certificate
and offset, or compare decoded logical bytes under explicit work and memory caps.
Victim-dependency proofs must inspect the physical compressed node, including its
header and encoded payload, rather than the virtual locator.

Range writes and truncation preserve native inode identity, hardlinks and explicit
metadata. New data nodes use the selected deterministic codec only when smaller
than NONE and within selected node caps; nodes outside those caps retain NONE. ZERO spans retain their existing semantics. Encoding charges twice the input length against the explicit byte-work cap; GC decoding shares one cumulative work counter across all files. RTIME encoder state reserves 2 KiB and ZLIB reserves 2 MiB, in addition to bounded input/output buffers. Capacity preflight uses
the complete aligned NONE worst case before any mutation. GC must relocate every
live reconstructed NONE, ZERO or supported compressed fragment, preserve required
history floors and tombstones, and prove complete logical equality and absence of
victim dependencies before durable COPIED. Adjacent packed records retain the
existing pristine-block allocation policy. Compression retains the planned NONE-sized positions, leaving erased FF gaps when encoded nodes shrink; it does not reuse partially occupied erase blocks.

Required acceptance includes both endian profiles; causal short source reads;
all allocation, cancellation and refund paths; rehashed semantic-negative intents
with zero target and journal writes; mutation and recovery interruptions under
all four target/journal volatile retention combinations; and native CRC plus
independent whole-payload extraction. Jefferson's historical isize/truncation
limitation remains explicit. Other codecs, physical NAND/OOB, mounted execution
and physical power-loss evidence remain unfinished scope.

## Evidence

The explicit ignored gate is `tests/fs_jffs2_edit_compression_native.rs`. Enable it with fresh `JFFS2_EDIT_CODEC_EVIDENCE`, `JFFS2_TOOLS` and `JFFS2_EXTRACTOR` paths; missing tools are fatal. Its fixed binary embeds engine/test sources and checks them against live files before and after the run, together with tool/parser/binary hashes.

The successful source-bound receipt is `/data/cache/partmgr-jffs2-edit-codec-native-run4/jffs2-compressed-edit-v1.txt` (SHA-256 `a4e5e72e4f8351a4850c9eae027ec1a534c870cf9f83c3a6941a1dd226dc2c37`); fixed binary `/data/cache/partmgr-jffs2-edit-codec-test` has SHA-256 `a475bcaf5c74a70db537aa4e1f0f98fa0a1cdbe5f2801ccbc7081a606c6d4644`. Exact argv, versions, source hashes, query text/hash, images and start/end checks are retained there. Twelve cases cover little/big endian RTIME/ZLIB and normal completion, a modeled partial-program error, and a modeled partial-erase error on real `FileStorage` with actual `sync_all` flushes. Matching recovery produces identical image hashes in all three cases for each codec/endian pair.

Independent mtd-utils 2.3.1 `mkfs.jffs2` supplies each source; `jffs2dump -c` validates completed native CRC histories and exact non-UTF8 name bytes. Jefferson 0.4.8's unchanged inode/codec/history decoder extracts both ASCII aliases and the complete 90,346-byte payload, including the extended ZERO tail, and the exact symlink target. Its stock directory index collapses hardlinks by inode, so the query uses Jefferson's own CRC-checked dirent parser to retain latest `(parent, native name)` entries before calling unchanged `dump_fs`; non-UTF8 names are excluded only from that UTF8-limited extraction query. Native hardlink identity is checked by the framework; separate extracted equal payloads do not establish host hardlink identity. The raw image, inode versions, data, and CRCs are never modified for the oracle.

Jefferson does not enforce historical shrinking `isize`: native evidence here deliberately covers extension, while truncation semantics have portable independent reconstruction tests. Neither the completed-image oracle nor modeled persistence cuts establish kernel mount behavior, hardware ordering or physical power loss. Other codecs and compressed authoring/editing profiles beyond RTIME/ZLIB remain unfinished family scope.
