# Common filesystem trees to staged optical images

The separate `integration/optical` development package enables `native-writer` for
`write::stage_iso` and `write::stage_udf`. Both consume an owned
`Arc<dyn partmgr::fs_core::TreeSource>` and shared `Resources`; no source directory
is extracted to the host. libmkiso owns ISO/UDF layout, encoding and emission.
The package manifest uses published version requirements only. Development
verification uses command-line Cargo patches, which do not prove crates.io API
availability.

The bridge inventories directories in bounded pages with explicit entry, byte and
extent limits. It maps source-scoped identities to optical inventory identities,
retains file hard links, rejects directory aliases/cycles, and detects destination
path collisions. Files must have exactly one ordinary `Data` stream. UDF additionally maps named
streams onto their owning file or directory and root `Named` / `System` streams
onto the corresponding file-set namespaces. ISO rejects named/root/system streams
before emission. Resource forks, non-root system streams, symbolic links and
special objects remain explicitly gated.
Deferred content retains the common positional `FileRead`, source tree, resources,
and shared accounting lease. Every read validates identity, captured logical length,
cancellation and source revalidation. Logical ranges must cover the whole stream
without gaps or overlap. Repeated reads never rely on a shared host seek cursor.

Native byte names require a declared interpretation: exact UTF-8, or eleven-byte
ASCII FAT 8.3 aliases converted explicitly to `BASE.EXT`. UTF-16 names decode only
valid scalar sequences; unpaired surrogates reject. Empty names, path separators,
NUL, dot/dot-dot, invalid UTF-8 and unsupported FAT aliases reject before emission.
Native bytes remain present in optical inventory alongside destination paths;
this does not promise optical on-disk names reproduce every original encoding.

Hard-link canonical targets are selected in the destination writer's depth/path
ordering, so an alias that sorts before the original source name still works.
ISO requires Rock Ridge for hard-link semantics. ISO materializes sparse and
unwritten ranges to zero bytes; UDF retains the advertised hole/allocated-hole
semantics with optical-block-aligned sparse boundaries. Adjacent logical data
ranges coalesce so physical source allocation boundaries do not constrain optical
layout. Unaligned UDF sparse boundaries reject during inventory, before payload
emission. Reports distinguish materialized and retained zero ranges. Named streams use
whole-stream deferred access: their sparse/unwritten allocation semantics transform
to recorded logical zeros, explicitly counted separately in the report.

`WritePolicy::ContentOnly` explicitly transforms native timestamps, ownership,
permissions, ACLs, attributes, flags, and opaque fields to destination defaults or
absence. Reports count inspected objects and discarded known, uninspectable, and
opaque fields. Known timestamps are never assigned an assumed epoch conversion.
`RequireMetadata` rejects before staging because validated cross-format timestamp,
owner/ACL and opaque-field mappings are not implemented. Content comparison is not
faithful filesystem capture.

Only genuine immutable snapshots or caller-guaranteed stable sources are accepted;
change detection alone is insufficient. Caller-guaranteed stability remains a
caller obligation. No authoring function publishes a destination. Each returns a
closed `StagedOptical` guard for inspection; dropping it deletes its temporary
image and refunds bridge accounting. Failures and cancellation leave no published
output. The caller owns any later publication protocol.

libmkiso's `TreeInventory` currently cannot retain a producer memory lease. The
adapter therefore keeps its `FileTreeSource` implementation private to the stage
functions. The returned guard retains a conservative shared reservation of four
metadata-byte caps plus 2048 bytes per possible entry, including directory-only
sources with no deferred payload handle. Inventory, traversal, maps, names,
continuations and deferred bridges remain charged throughout staging and guard
lifetime. Common-source pages/metadata/file indexes reserve from the same pool.
libmkiso's internal writer allocations remain subject to its own advertised
metadata limits; this bridge does not establish exact shared-budget accounting
for every allocation inside that external library. Exporting a general public
inventory bridge requires an upstream retained-lease contract.

Tests author ISO/Rock Ridge and UDF from independently constructed common-source
fixtures with a 90,003-byte payload, an 8192-byte hole, and file aliases whose sort
order precedes the original name. Reopened readers compare exact bytes with the
independently generated expected payload; UDF aliases share the same ICB.
An additional UDF 2.60 test emits an 8,000,123-byte named stream under a 4 MiB
shared resource limit, plus root, system and directory-owned streams, using generated positional
inputs without whole-file source buffers. Reopened UDF reads use 8192-byte buffers
and compare every expected byte, file/directory ownership, and root/system associations.
An unaligned hole within the named stream explicitly materializes to recorded
logical zeros, and the corresponding transformation counter is verified.
Tests also cover explicit FAT/UTF-16 name mappings, invalid names, strict metadata
rejection, deferred I/O failure, cancellation during payload access, empty-tree
lease retention, staging cleanup and reservation refunds. These tests validate
library integration, not native-tool interoperability or firmware boot behavior.

Development verification:

```sh
cargo test --manifest-path integration/optical/Cargo.toml --features native-writer \
  --config 'patch.crates-io.partmgr.path="/path/to/partmgr"'
```

The same partmgr override is used for `cargo clippy ... -- -D warnings`. All four
writer tests and strict Clippy now pass against published crates.io libmkiso 0.1.4.
The new partmgr APIs remain a separate release gate.

`integration/optical/tests/hfsplus_capture.rs` verifies the unsupported
resource-fork boundary using the audited HFS+ engine and an independent indexed
catalog/overflow fixture. Both ISO and UDF capture refuse the stream before any
staged file appears, including under ContentOnly; resource forks are not silently
excluded. A future preserving profile must specify their output semantics and
verify a native round trip before claiming support.


Resource forks require an explicit transformation. The additive
`WritePolicy::ContentOnlyResourceForkAsNamedStream` emits each non-root resource
fork as a UDF named stream `com.apple.ResourceFork`, retaining its owning object
and exact deferred logical bytes. UDF 2.00 or newer is required. The report counts
`resource_forks_as_named_streams`; this preserves content while transforming
native fork semantics, and does not claim faithful metadata capture. Existing
`ContentOnly` still rejects resource forks; ISO rejects all auxiliary streams.
Mapped-name collisions reject before authoring. Root resource forks remain
unsupported. The APFS integration test opens an independently constructed,
complete-audited source and checks its full sparse data, exact resource bytes,
stream ownership, default-policy rejection and staging cleanup/refunds.
