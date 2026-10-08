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
Image length is 1–128 MiB; the initial layout uses one spaceman chunk/CIB and
volume OID 1026. This bound is not full APFS destination-family completion.

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
before mutation. Unwritten allocation, named/system streams and special objects
remain explicitly unavailable in this authoring profile.
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

`ApfsBuildPlan::plan_with_checkpoint_capacity` accepts additive `ApfsCheckpointCapacity { descriptor_blocks, data_blocks }`; existing `plan` retains byte-identical 8/8 defaults. Descriptor capacity must be even in 8–128 blocks and data capacity a multiple of four in 8–256; geometry must fit before inventory. Capacity changes construct all relocated native identities, mappings and bitmaps, rather than patching a formatted fixture. The supported one-chunk/CIB topology has an exact six-block internal pool, as required by its native allocation topology. Expanded rings allow two retained COW publications; they do not authorize arbitrary pool enlargement, reclamation or unbounded editing.
