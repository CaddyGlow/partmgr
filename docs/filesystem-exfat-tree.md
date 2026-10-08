# exFAT common tree source

`fs_exfat_tree::ExfatTreeSource::inventory` wraps the strict immutable
`ExfatVolume` profile as a common `TreeSource`. It completes namespace inventory
before returning, with separate limits for objects (including root) and aggregate
directory allocation clusters. Directory maps may not overlap: aliases, cycles,
and chains sharing a cluster are rejected. Parents come from containing entry
sets; exFAT has no dot or dot-dot entries. File allocation ownership is not globally
audited, and shared file allocations are not treated as hard links.

Names retain exact native UTF-16 units, including unpaired surrogates. The volume
reader validates checksums, name hashes and duplicate names using the validated
on-volume upcase table. The adapter does not implement a second codec or folding
table. Object identities are physical directory slots scoped to the volume open.
Continuation tokens bind to the source, generation and directory identity.

Inventory reserves memory before allocating its maps and traversal queue. Native
entry locators retain their complete directory decoder and lease; pages and
metadata own additional refundable leases. Opening ordinary data streams builds
a bounded file index and retains a positional `FileRead`, without buffering the
payload. Root and directories have no ordinary stream; named streams and resource
forks are unsupported by this accepted exFAT profile. Uninitialized file tails are
read as zeros through the volume reader.

Packed timestamps, 10ms increments and UTC-offset bytes are exposed as opaque
native fields, without guessing an epoch or decoding a timezone. File attributes
are known native flags. Unix ownership, modes, ACLs, symlink and reparse metadata
are absent in this accepted baseline profile. The implicit root has no native file
entry timestamps or attributes. Unsupported native critical entries remain reader
gates, not inferred metadata.

The caller guarantees source stability. Every callback checks cancellation and
source length, and rejects foreign or stale object identities. Length checks do
not detect in-place changes with unchanged length and do not establish a snapshot.

Validation: `cargo test --locked --test fs_exfat_tree` uses an independently
assembled specification fixture, without a production writer. A 130,123-byte file
is compared byte-for-byte using 4KiB reads, including a poisoned backing tail
beyond its 100,003-byte valid-data length. Tests also cover surrogate names,
pagination and token scope, nested inventory, opaque metadata, deferred handles,
object/directory limits, aliases, cycles, folded duplicates, cancellation, source
length changes and complete memory refunds. These host tests do not establish a
native-tool oracle, Windows servicing or firmware behavior; native volume-reader
evidence is documented separately in `filesystem-exfat-volume.md`.
