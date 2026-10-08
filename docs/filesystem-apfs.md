# APFS immutable reader and complete initial-profile audit

`ApfsContainer::open` selects a checksummed checkpoint, and `ApfsVolume::open`
requires an explicit volume object identifier. `ApfsTreeSource::inventory` requires
a complete clean audit. Source identity uses domain 16 and checkpoint XID as its
generation. The caller must hold the source stable for the lifetime of every
handle; length checks and metadata rereads do not detect arbitrary same-length
payload replacement.

The accepted initial profile is a bare, exact-length, 4 KiB-block container with
multiple explicitly listed volumes and structurally complete historical checkpoint
candidates, unencrypted case-sensitive and
normalization-sensitive names, ordinary files and directories, regular hardlinks and same-volume unencrypted
clones with verified native reference counts, explicit sparse
file extents, and resident resource forks. Native UTF-8 name bytes, POSIX mode,
UID/GID and nanosecond timestamps are retained. Data and resource forks are
separate streams. Raw inode fields, Finder information, embedded attributes and
volume metadata remain opaque preservation requirements. The reserved empty
private directory is retained as opaque root metadata rather than emitted as a
user directory. Unknown metadata is never a claim of faithful conversion.

Discovery checks Fletcher64, descriptor/data-ring bounds, checkpoint mapping
identity and every mapped ephemeral object's checksum. Malformed structural
checkpoint candidates can fall back to an older candidate; unsupported state,
I/O errors, cancellation and resource exhaustion fail the operation. Object-map
selection uses the greatest mapping XID no newer than the selected checkpoint.
B-tree nodes validate storage identity, levels, record intervals, key ordering,
child minima, traversal cycles and root totals. File maps retain physical tails
through the final allocated block and defer payload I/O. Explicit holes read as
zero. Opening a stream currently repeats the complete audit before publishing
its map; no metadata-cache performance claim is made.

The audit checks container and volume object maps, filesystem and physical
extent-reference trees, spaceman chunk bitmaps and CIB summaries, the internal
pool bitmap ring, empty free queues, inactive reaper state, metadata ownership,
all physical file extents, namespace references, reachability and native link
counts. Crosslinks, referenced-free blocks, lost allocations or checkpoint-copy
disagreement suppress every free range. Unsupported structures fail the whole
operation. A clean report means a coherent complete allocation/reference proof
for this profile. It does not establish a macOS unmount, journal replay, repair,
exclusive write authority, or permission to discard those ranges.

Limits bound blocks, checkpoint blocks, objects, records, traversal depth,
findings and work. Reservations precede indexed allocations and remain leased
with retained handles; failed operations and dropped handles refund them.
Metadata and ownership traversal have separate bounded work phases within the
audit's configured cap. Cancellation and source errors propagate through deferred
reads, including calls at EOF.

Snapshots, cross-volume physical sharing, directory hardlinks,
encryption, compressed files, external xattr streams, legacy hardlinks without
bidirectional sibling maps,
hashed insensitive directory keys, fragmented B-tree free lists, fusion and
additional device tiers, active reclaim queues and extended inode structures
are explicitly unsupported. These are remaining APFS family scope, not completed
profiles.

The format reference is Apple's [Apple File System Reference](https://developer.apple.com/support/apple-file-system/Apple-File-System-Reference.pdf).
The independent byte fixture constructs native objects without invoking the
reader. Its extended-field used-data count follows observed native layout and
apfsprogs implementation: it excludes the field descriptor array.

Run the enabled native gate with a fresh evidence directory:

```sh
PARTMGR_APFS_NATIVE_EVIDENCE=/data/cache/partmgr-apfs-native-v1 \
  CARGO_TARGET_DIR=/data/cache/rust cargo test --test fs_apfs --locked \
  native_formatter_checker_payload_and_fork_receipt -- --ignored --exact
```

Missing tools fail an enabled gate. It uses experimental Linux apfsprogs 0.2.1
and Sleuth Kit 4.14.0, inserts an independently authored populated native tree,
checks the volume with `apfsck`, compares separately extracted data and resource
forks, and checks image hashes before/after validators. Compiled source bytes,
test-binary and tool hashes are recorded before commands and verified afterward;
commands, stdout, stderr and exit status have separate retained files. TSK `fls`
misrenders normalization-sensitive directory names; raw output is retained and
`istat` names and the independent checker provide the available name evidence.
No Apple-generated fixture or macOS `fsck_apfs`/mount evidence has been established.

The current retained native receipt is
`/data/cache/partmgr-apfs-native-v4`: 16,384 total blocks, 16,181 free and 203
allocated, matching the independent pool oracle. Exact inode names, both file
payloads and the resource fork passed comparison. Earlier probe and failed-gate
directories remain historical evidence and are not substituted for this receipt.


## Multiple volumes and checkpoint ownership

The audit visits every listed volume, including unselected volumes. A caller's
explicit volume OID controls the emitted namespace; it does not narrow the
allocation proof. Container object-map pages are counted once. Volume-native
slot references and UUID uniqueness are checked. Unsupported state in another
volume prevents a complete proof and never exposes partial free ranges.

Every structurally complete older candidate still present in the descriptor
area is inspected conservatively. The latest complete candidate remains selected;
unsupported newest state is not bypassed by selecting an older volume. Checksummed
but incomplete candidates are excluded from selection; ambiguous equal-XID
candidates are rejected. Shared unchanged metadata and identical volume/stream/
logical-block ownership across generations are counted once. Conflicting owners,
historical references to currently free blocks, and unexplained latest allocations
suppress free ranges. Old main and internal-pool bitmap metadata is included in
the union, while the selected checkpoint's bitmaps determine free space. This
conservative candidate policy can reject images whose older valid descriptor
slots are stale; it does not infer that every slot was retained by a macOS mount.
Active reclaim queues and snapshots remain unsupported.

Namespace occurrences and audit work are capped across volumes and checkpoint
generations. Historical discovery, newly decoded volumes, ownership traversal
and union visits consume the aggregate audit work cap. Source-binding stability
rereads also have their own read-work ceiling. Metadata leases can coexist during
historical traversal, so callers must provide enough shared memory for the chosen
caps; exhaustion fails and refunds all temporary leases. The tests use an explicit
256 MiB budget for multiple-volume historical traversal.

The spec requires the maximum-volume field to be the container's size divided by
512 MiB, rounded up and capped at 100. A valid two-volume independent fixture
therefore exposes 536,875,008 logical bytes through a checked zero-padding source,
while storing only its 2 MiB metadata/payload prefix. It describes all 131,073
blocks with five CIB chunk records. The earlier tiny two-volume draft was invalid
and is not accepted evidence.

The expanded profile's current source-bound receipt is
`/data/cache/partmgr-apfs-native-v11`. It preserves the 64 MiB populated image's
203-block allocation and data/resource/nested payload comparisons, then formats a
sparse 536,875,008-byte container and independently inserts a second volume and
new checkpoint mappings. `apfsck` accepts the result; TSK reports selected XID 2,
volume OIDs 1026 and 1100, 131,073 total blocks and 130,624 free blocks. Both
explicit framework volume selections obtain a clean 449-block container proof;
TSK filesystem reports for both volumes and image immutability hashes are
retained. The two native volumes are empty: historical relocation and conflicting
historical ownership are established by the separate independent byte fixtures,
not claimed as experimentally formatted payload evidence. Published experimental
tools do not provide a general multi-volume/history authoring interface, so raw
fixture insertion provenance remains explicit.


## Regular hardlinks and clones

Regular hardlink directory occurrences carry a native sibling-ID xfield. The
reader checks each occurrence against its sibling link and sibling map, exact
UTF-8 name, parent and target inode; the lowest sibling ID must agree with the
inode's primary name and parent. Sibling IDs cannot collide with inode or data
stream IDs. Native link counts are exact. Directory hardlinks, dangling siblings,
map mismatches and unknown directory xfields fail. Raw directory records,
sibling links and sibling maps remain opaque preservation metadata. Every alias
has the same common object identity; distinct clone inodes remain distinct.

Clones can share a private data stream, or have separate data streams referencing
some of the same physical blocks. Per-stream run indexes are immutable and
shared without copying their entire extent lists. The native data-stream count
must equal the number of referring inodes, independently of hardlink occurrence
counts. Shared streams must agree on logical and allocated sizes and carry
native clone provenance flags. Crypto state and external resource-fork data
streams remain gated.

For each volume/checkpoint, the audit counts distinct data-stream references to
every physical block and compares them exactly with positive signed native
physical extent counts. One data stream referencing a block at more than one
logical offset is counted once. Extent records must cover those blocks without
overlap and have an in-range original owner identifier; the original inode may
have been removed. Native clone flags are required for separately shared streams.
Physical blocks are counted once for volume allocation summaries. A record's
original owner identifies historical sharing; reference counts are verified
separately in each checkpoint and are not added across generations. Metadata/data
aliases and sharing across volumes still fail the global ownership proof. Every
shared block remains allocated and excluded from reported free ranges.

Independent fixtures cover both clone representations, regular hardlink aliases,
historical transitions from an unshared to a shared file, cross-volume conflicts,
rechecksummed sibling/name/parent/reference/flag defects, and resource failures.
The experimental native gate inserts the same raw record structures into its
populated formatter image, runs `apfsck`, checks TSK's two-link inode report, and
compares cloned file bytes against both TSK and the original payload. This is
read-only interoperability evidence, not a macOS clone-operation or copy-on-write
mutation claim.

The current sharing receipt is `/data/cache/partmgr-apfs-native-v13`.
`private-stream-clone.receipt` and `distinct-clone.receipt` both pass with 203
allocated blocks, native inode 16 having two links and clone inode 21 yielding
identical sparse payload bytes. Both independent checker runs have empty
stdout/stderr; both fixture clone flags are explicitly consistent. The gate also
reruns the earlier populated/fork and multiple-volume/checkpoint evidence with
fresh source, binary and tool bindings. Earlier receipts describe their exact
historical sources.
