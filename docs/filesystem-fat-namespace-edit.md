# Owned FAT namespace transactions

`FatEditor` now creates regular files and directories, renames or moves either kind, and deletes files or empty directories. These operations use the same exclusively owned storage session, complete allocation/reference audit, external undo journal, and generation invalidation as existing range replacement and resize operations. They do not expose arbitrary physical writes.

Open a parent with `open_directory`, supplying exact `NativeName` components (an empty path selects the root). Its identity and every returned entry identity carry the current editor generation. A committed operation invalidates earlier handles and batches. Directory handles retain bounded decoded facts rather than an independent storage capability. Planning and committing check cancellation and the session state; uncertain commits require recovery and reinspection before further editing.

## Explicit names and metadata

`FatEditName` supplies an exact padded eleven-byte short alias, an optional exact VFAT UTF-16 spelling, and a `FatNamePolicy`. No alias, codepage conversion, Unicode normalization, or clock value is generated. `AsciiCaseInsensitive` rejects unsupported non-ASCII comparison contexts and checks new short and long spellings against both existing namespaces. `CallerVerifiedNativeCaseDistinct` is an explicit caller assertion about native OEM/Unicode case distinctness; exact and ASCII-folded collisions still reject. It does not establish a volume-wide Unicode case audit.

Illegal aliases, malformed UTF-16, names longer than 255 UTF-16 units, dot names, and leading/trailing-space or trailing-dot spellings needing normalization reject. Existing normalization-sensitive comparison contexts reject. VFAT slots use independently checked association, reverse ordinal order, the short-alias checksum, and exact native termination/padding.

Creation uses `FatCreateMetadata.raw`, a native 32-byte slot template. Name, first-cluster, and size fields must initially be zero; attributes must match the requested object kind. Native date/time fields are validated and copied, including explicitly supplied unknown/zero fields. `zeroed(attributes)` is an explicit unknown-time policy. Rename preserves existing native metadata except the requested name and, for a directory moved between parents, its `..` pointer. Delete tombstones the associated slots and preserves their remaining bytes. Read-only objects cannot be renamed or deleted; volume labels are outside this profile.

## Allocation and recovery

`plan_create_file` accepts bounded bytes; `plan_create_directory` initializes canonical `.` and `..` entries. `plan_rename` supports a same-parent rename or a move into another directory. Parent growth allocates and initializes new directory clusters before linking them. Fixed FAT12/16 root directories cannot grow. Moving a directory into its descendants rejects, and native dot references must match the actual topology. `plan_delete` rejects nonempty directories and never recursively deletes or shrinks the parent chain.

Shared allocation planning preserves packed FAT12 neighbors, selected FAT mirrors or the active FAT, FAT32 reserved high bits, and unrelated bytes. New payload clusters and unused tails are initialized before references are published. Existing free directory slots are prepared while their first bytes remain unpublished, then published in a later stage. Delete durably removes references before releasing allocation. Every stage writes, flushes, and verifies before the next stage; the complete undo body is durable before any target stage. The external journal must satisfy the caller-verified disjointness binding contract: owning two handles alone does not prove separate media.

Validated primary and supported backup FAT32 FSInfo counters and hints are maintained from the complete ownership audit. Unsupported FSInfo layouts reject. Known stale counters are explicitly reconciled and reported. A successful namespace commit reinspects the resulting allocation and namespace before returning the session to its ready state.

`FatNamespaceReport` records the operation, exact new names and comparison policy, allocation/free counts, parent growth, metadata preservation policy, and FSInfo reconciliation. Work, slots, objects, file clusters, affected bytes, patch count, journal bytes, and shared memory all have explicit limits. Reservations cover retained directory facts, planning scratch, reports, and the undo plan, and refund on drop or rejection.

## Validation

Independent packed-FAT fixtures test create/move/delete, empty-directory rules, cycle and corrupt-dot rejection, generation identity rebinding, collision policies, caller metadata, maximum-length VFAT names across fragmented directory growth, bad-cluster neighbor preservation, cancellation and budget rejection. Fault tests inject every actual write/barrier failure, including a partial target write, and exercise both continuing-owner recovery and restart models that retain or discard unflushed writes. Whole-container comparisons accept only the original or fully authorized final image.

The explicit native gate requires installed `mkfs.fat`, `mcopy`, `mmd`, `mdir`, and `fsck.fat`; enabling it without tools or a fresh absolute evidence destination fails:

```sh
PARTMGR_FAT_NAMESPACE_EVIDENCE=/data/cache/partmgr-fat-namespace-native-20261008-final \
  cargo test --all-features --locked --test fs_fat_edit_namespace \
  native_fat12_16_32_namespace_every_io_cut -- --ignored --nocapture
```

The gate independently formats FAT12/16/32 fixtures, imports deterministic payloads larger than 64 KiB with mtools, and independently fills existing directory slots to force growth. It retains source snapshots and hashes, the exact gate binary and hash, tool paths/hashes, exact commands and native outputs, image/journal files, extracted payloads, and per-case whole-image and outside-patch comparisons. Native evidence concerns regular-file injected IO and recovery models; it does not establish physical-device power-loss or firmware behavior.

The final gate passed on 2026-10-08 in 224.72 seconds: 27 normal cases and 877 injected write/barrier/torn-write failures, totaling 904 cases. FAT12 and FAT16 each exercised 267 failure cuts; FAT32 exercised 343. Nine operation classes cover file creation with and without parent growth, directory creation, file and directory moves, file and empty-directory deletion, short rename, and shortening a mtools-created VFAT name. Native cuts use continuing-owner recovery; the separate deterministic fault test exercises restart with both retained and discarded unflushed writes.

Evidence: [receipt](/data/cache/partmgr-fat-namespace-native-20261008-final/receipt.txt), [hash verification](/data/cache/partmgr-fat-namespace-native-20261008-final/verification.json), and [enabled-gate negative controls](/data/cache/partmgr-fat-namespace-final-negative/control.json). All eleven captured source files matched the current originals and retained snapshots at completion; the retained binary also matched the negative-control binary. Every archived native stdout/stderr hash and all 27 retained committed-image hashes were independently checked. Missing tools and a missing evidence destination both failed with exit status 101. These receipts supersede the development `v2` namespace run for this source snapshot.

Encoding and namespace rules follow the Microsoft FAT specification, particularly directory structure, VFAT entries, FAT allocation, and FSInfo: [Microsoft FAT specification](https://www.scs.stanford.edu/~zyedidia/docs/_other/fat.pdf).
