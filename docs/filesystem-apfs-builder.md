# APFS offline construction contract

This work authors a fresh unpublished APFS container from `TreeSource`. It does
not use a preformatted image, invoke a formatter as its implementation, or modify
an existing filesystem. Existing-volume copy-on-write editing and restartable
recovery remain separate required work.

The accepted initial construction profile uses 4096-byte blocks, one physical store, one explicitly
identified unencrypted case-sensitive and normalization-sensitive volume, and a
single initial transaction at XID 1. Container and volume UUIDs, volume label and
metadata defaults are explicit inputs. No wall-clock time, random identifiers or
source codec are required to serialize the destination.
Image length is 1 MiB through 512 MiB plus one 4096-byte block. The bounded layout
uses up to five 32768-block spaceman chunks, one CIB and volume OID 1026. This bound is not full APFS destination-family completion.

The native structures are constructed from field definitions: NX superblocks,
descriptor/data checkpoint rings and checkpoint mappings, ephemeral reaper and
space manager with empty free queues, main-device and internal-pool bitmaps and
chunk summaries, container and volume object maps, catalog B-trees, physical
extent-reference B-trees and an empty snapshot metadata tree. Object checksums
cover initialized blocks. Virtual catalog objects have explicit OMAP bindings;
physical objects retain native physical identities.

Planning inventories the common source under independent object, occurrence,
name-byte, depth, block and work limits and shared memory reservations. It checks
native name representability and collisions, retains regular hardlink identity,
binds each opened stream's identity and length, and performs metadata preflight
before writing. Exact byte names must already be valid APFS UTF-8; conversion
from UTF-16 is a separate explicit policy. Unsupported special objects, streams
or preservation requirements fail preflight rather than disappearing.
`ApfsBuildMetadata::ContentOnlyDefaults` explicitly replaces source ownership,
permissions, timestamps, ACLs, attributes and flags with selected native defaults
or omissions. `outcomes()` retains each object's class inspection status and
transformation decision, including opaque and uninspectable classes.
`RequirePreservation` rejects before mutation. The report records the defaults,
transformed-object count and actual UTF-16 name conversions. Names and inode
assignment follow a canonical name-sorted topology, independent of source page
or enumeration order; no host or reconstructed display paths are used.

Payloads remain deferred. A block whose entire logical range is a hole can remain
unallocated, including the final block at EOF. Mixed blocks require initialized
physical bytes containing the same logical zeros. Resource forks up to 2048 bytes
are authored as separate embedded native streams; larger/external forks reject
before mutation. Unwritten allocation, system streams and special objects remain explicitly
unavailable. The default constructor rejects Named streams. The additive
`plan_with_named_xattrs` constructor accepts explicit stream-count and total-name
byte caps and preserves dense user xattr values as deferred external native
streams, including directory values. Names must be exact UTF-8 byte names; sparse
or unwritten values, dedicated ResourceFork/FinderInfo/security/compression names
and `com.apple.fs.*` semantics reject before destination mutation.
`named_stream_outcomes()` records every mapped source object, exact name and
logical length. Content-only metadata defaults remain explicit: this mapping
preserves names and bytes, not source physical stream IDs or write counters.
Hardlinks share one inode and stream while each native namespace occurrence has
matching sibling link/map records. Source physical clone relationships are not
inferred from equal bytes; independent objects retain distinct destination
streams unless a future explicit clone policy proves the relationship.

Emission requires exclusive access to an unpublished exact-length target. It
initializes the entire image, writes and verifies payload bytes, then writes
checksummed metadata and the complete checkpoint only after its prerequisites.
Durability barriers and readback are explicit. An error or cancellation leaves
an unpublished staging artifact; it never represents a successful publication
or a recoverable transaction on a previously mounted volume. The orchestrator
must reopen the completed image, run the complete APFS allocation/reference audit,
verify namespace and stream bytes and revalidate source bindings before publishing.
`ApfsBuildPlan::plan` binds the common tree and produces the reviewable plan;
`emit` returns initialized-image SHA-256/readback evidence, and
`ApfsBuildReport::audit` verifies exact length/hash and runs the reopened complete
allocation/reference audit. Emission and verification retain source and operation
cancellation, propagate underlying I/O failures and refund reservations on error.
The mutable target implements `Storage`; it does not become an immutable `ReadAt`
source during writing. Reopen a read-only source after emission for the audit.

Limits cap unique objects, occurrences, names, depth, image/logical mapping blocks
and planning work, including sorting and checksummed serialization. All source
logical lengths fit the selected image-byte ceiling. Indexed holes count toward
the mapping bound; many sparse streams cannot build an uncharged mapping graph.
Emission scratch is three 4096-byte blocks, while deferred maps, inventory and
metadata outcomes retain conservative shared reservations. Reopened full-image
hashing is charged against read work before I/O. The report exposes actual source
stability; generation checks and readback do not create snapshot isolation, so
the caller must keep deferred source bytes stable for the complete operation.

The retained native receipt is
`/data/cache/partmgr-apfs-build-native-v12`. A source-codec-independent common
tree with 1500 regular files plus one nested file forces internal catalog,
extent-reference and volume OMAP nodes. Framework construction initializes a
64 MiB file through actual `sync_all` barriers, closes it and reopens read-only.
The complete framework audit and independent `apfsck` pass; TSK reports the same
1679 global allocations, hardlink count two, exact Unicode primary name, all
16397 expected ordinary bytes (including holes), separate resource bytes and the
distinct object's identical logical payload. The volume allocation count is
1637. Validation leaves the image hash unchanged. TSK `fls` output is retained,
but its known unhashed-directory-name rendering limitation is not treated as a
faithful occurrence-name oracle. [TSK 4.14.0 directory decoding](https://github.com/sleuthkit/sleuthkit/blob/sleuthkit-4.14.0/tsk/fs/apfs_fs.cpp#L113-L135)
unconditionally uses the hashed key’s 12-byte header; this profile uses the
native unhashed key’s 10-byte header, dropping the first two name bytes.
Framework lookup checks every emitted occurrence, `apfsck` validates native
directory keys, and TSK `istat` independently checks inode primary names. An
independent complete occurrence-name oracle remains an evidence gap.

The gate records compiled source/binary digests before commands, tool digests and
version attempts, command/output/status layers, and matching source/tool digests
at completion. `apfsck -V` does not supply a version and its failed attempt is
retained; package provenance and exact binary digest identify the tool. Earlier
v1–v5 failures and v6–v11 earlier successes remain historical receipts.
Ordinary tests additionally cover deterministic output under reversed source
enumeration and differing per-object generations, malformed/capped inputs, unsupported names/classes/streams,
generation/length/cancellation failures, short/torn writes, every durability
barrier failure, prerequisite readback defects and memory refunds.
Experimental Linux checkers do not establish macOS mount, Apple formatter/fsck,
encryption, snapshot or copy-on-write recovery correctness.

The primary structure definitions are Apple's [Apple File System Reference,
2020-06-22](https://developer.apple.com/support/apple-file-system/Apple-File-System-Reference.pdf).
The independent experimental construction/checking comparison uses
[apfsprogs](https://github.com/eafer/apfsprogs), whose layout choices are compared
against the specification rather than treated as mandatory geometry.

`ApfsBuildPlan::plan_with_checkpoint_capacity` accepts additive `ApfsCheckpointCapacity { descriptor_blocks, data_blocks }`; existing `plan` retains byte-identical 8/8 defaults. Descriptor capacity must be even in 8–128 blocks and data capacity a multiple of four in 8–256; geometry must fit before inventory. Capacity changes construct all relocated native identities, mappings and bitmaps, rather than patching a formatted fixture. The internal pool is exactly three times the chunk/CIB/CAB count: six blocks for one chunk and one CIB, eighteen for five chunks and one CIB. Construction initializes one native bitmap per chunk with exact population/free counts. Native ephemeral-info and maximum-volume fields derive from container size. Expanded rings allow bounded repeated publications; each consumes unused internal-pool blocks for affected chunk bitmaps and a CIB. Six consecutive publications are demonstrated on the five-chunk authored image; arbitrary pool enlargement, reclamation and unbounded editing remain unsupported.

A subsequent construction draft accepts up to 127 allocation chunks through two direct CIBs, retaining the existing default serialization. Each native CIB contains at most 126 ordered chunk entries with its exact index; the spaceman address table identifies both objects, and the internal pool is exactly three times the total chunk/CIB count. Explicit image/block/work/memory limits remain required. CAB-based geometry is rejected. This draft extends actual native construction rather than patching a preformatted fixture, but is not qualified by the historical five-chunk builder/native receipts above; separate multiple-CIB native evidence remains pending.

The direct two-CIB native construction checkpoint is retained at `/data/cache/partmgr-apfs-cibs-native-v4`. It archives 26 embedded compiled sources and a fixed executable, with start/end source, executable and tool guards. Four framework-authored checkpoints on a 16,919,822,336-byte container pass the experimental native checker and complete TSK sparse DATA/resource/name/link/owner comparisons. Ordinary planning controls prove deferred payload reads and refusal/refunds for third-CIB geometry and insufficient memory. The native parameter profile uses the pinned formatter's piecewise main free-queue node limit, including 512 nodes at four GiB and above. Earlier native attempts and the corrected independent-fixture provenance remain explicit; this does not establish macOS kernel behavior, CAB construction or broader encrypted/multiple-store profiles.


Named-xattr capture qualification uses an independent common TreeSource, not a
preformatted-image template. Planning reads no payload bytes; emission revalidates
identities and lengths, writes/readbacks values, and a reopened complete audit
checks physical xattr ownership. Portable tests cover root and ordinary directory
values, stale-plan zero-write refusal, explicit caps and lease refunds.

The native gate `native_named_xattr_fresh_construction_files_directories_and_exact_values`
requires `PARTMGR_APFS_NAMED_BUILD_EVIDENCE` and fails if its checker or TSK tools
are unavailable. It checks complete independent DATA/resource and five Named
value models, including a 7001-byte directory value, and retains compiled source,
fixed executable, tool hashes and unchanged-image guards. This is Linux
experimental-checker evidence, not a macOS mount or write claim.

Two native oracle gaps remain explicit. Root xattrs have native physical owner
ID 2 under Apple's inode-owner rule; the framework proves those mappings, but
the pinned experimental checker rejects the reserved owner ID. The native clean
gate therefore covers ordinary directories and files, while root values have
portable format/audit tests only. Pinned TSK 4.14.0
[APFSJObject directory parsing](https://github.com/sleuthkit/sleuthkit/blob/sleuthkit-4.14.0/tsk/fs/apfs_fs.cpp#L113)
unconditionally assumes the hashed 12-byte directory key. This profile's native
normalization-sensitive key is 10 bytes, so `fls` truncates its names. Inode xfield
names and full stream extraction remain usable independent evidence; truncated
`fls` output is not claimed as exact native namespace verification. The producer
does not change native key encoding to accommodate that oracle limitation.
