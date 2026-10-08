# Classic ext2 tree adapter

`ExtTreeSource::inventory` implements `TreeSource` over the strict immutable,
Linux-created, clean 128-byte-inode ext2 profile. It inventories the reachable
namespace with object, name-entry, per-stream block and directory-slot limits.
Reservations remain attached to inventory, pages, metadata and deferred indexes.
Regular files retain positional reads; symlink targets are inspected under a
separate retained memory lease and never followed. Hard links, including symlink
hard links, retain one source-scoped inode/generation identity with distinct names.

Each directory must have one correct dot and dot-dot reference. Directory aliases
and cycles reject inventory. Pages preserve exact native bytes, including invalid
UTF-8. Continuation tokens bind source, generation, inode and page position.
Callbacks re-read inode identity and check cancellation; the retained checked
source also checks its original length. This is `CallerGuaranteedStable`, not a
snapshot: callers must prevent in-place changes with unchanged length/generation.

Unix mode is `Known`. Ownership is `Known` native bytes: little-endian 32-bit UID
followed by little-endian 32-bit GID, combining Linux low/high 16-bit components.
Modification/access timestamps preserve their exact four little-endian native
bytes as `Opaque` fields; no epoch, signedness or timezone conversion is guessed.
`ext2.inode.ctime` preserves change time as an opaque attribute, not creation time.
`ext2.inode.dtime` preserves the deletion-time field: the strict reader requires
zero deletion time and a nonzero link count. Creation time is absent. Native flags
are known bytes; nonzero flags remain an unsupported reader gate. External xattrs
are gated, and ACL/security data are absent in the accepted no-xattr profile.

Symlinks expose `Known` exact byte targets in metadata and have no data stream.
Inline storage is selected by zero `i_blocks` (external ACL blocks are unsupported),
requires a target shorter than 60 bytes and its terminating zero. Block-backed
storage uses the existing checked classic block index under the same block and
memory ceilings. Empty targets, embedded zero bytes and malformed maps fail.
FIFO, socket, character-device and block-device inventory explicitly rejects as
unsupported. Named streams are unsupported. The allocation audit deliberately
continues to gate symlinks; tree support does not broaden audit support or claim
cross-inode ownership, lost-block or link-count auditing.

The encoding follows the primary Linux [ext2 inode structure](https://raw.githubusercontent.com/torvalds/linux/master/fs/ext2/ext2.h)
and [ext2 inode implementation](https://raw.githubusercontent.com/torvalds/linux/master/fs/ext2/inode.c),
including UID/GID composition, distinct access/change/modification/deletion fields
and zero-sector fast-symlink selection. The [kernel ext2 documentation](https://www.kernel.org/doc/html/latest/filesystems/ext2.html)
describes native byte names and the short-symlink storage optimization.

Host tests independently assemble malformed/topological and non-UTF-8 fixtures.
They check exact inline and external targets, high UID/GID bits, opaque timestamps,
hard links, pages, stream gates, cancellation, limits and reservation refunds.

The native evidence gate is explicitly ignored by default. Enable it with:

```sh
PARTMGR_EXT_TREE_EVIDENCE=/absolute/evidence/destination cargo test --locked --test fs_ext_tree -- --ignored --nocapture
```

An enabled gate fails if the destination or any native tool is missing. It retains
an 8MiB image independently formatted using `mke2fs -q -F -t ext2 -O none -I 128`,
a deterministic 100,003-byte file, and the exact debugfs script. Debugfs creates
hard links and short/long symlinks, sets UID 70001/GID 80002 and distinct native
timestamps 1700000001/2/3. Native `stat` output confirms ownership, modification
encoding, fast symlink and allocated long symlink. Tree metadata and payload bytes
are compared independently; `e2fsck -fn` passes and the image remains byte-identical.
The receipt records executable paths/hashes, tool versions, command descriptions,
source/lockfile/image/payload/script hashes and every retained native-output hash;
artifacts and receipt are synced before success. This is host filesystem evidence,
not Windows servicing or firmware evidence.

The enabled gate passed with e2fsprogs 1.47.4 on 2026-10-07. Retained receipt:
`/data/cache/partmgr-ext-tree-metadata-evidence/517-1791410018888462267/receipt.txt`.
The external symlink was also dumped through debugfs and independently compared
with its exact target. A deliberately empty tool search path produced exit 101
and no success receipt; its output is retained in
`/data/cache/partmgr-ext-tree-missingtools-evidence/control.txt`.

For the explicit immutable 256-byte Linux inode profile, timestamps retain opaque native seconds plus declared epoch/nanosecond words, and declared birth time is opaque rather than absent. The exact checked inode extension is also exposed as a native attribute. See [immutable profiles](filesystem-ext-profiles.md); this does not authorize extended-inode editing or imply default ext4 feature support.

The modern [ext4 profile](filesystem-ext-profiles.md) retains structurally/checksum-validated native xattr containers as an opaque `ext.xattrs` attribute. Its framing contains four little-endian u32 fields (inode number, external block number, inline byte length, external byte length) followed by exact inline/external container bytes. Security metadata is uninspectable because ACL/security value meanings are undecoded; opaque bytes carry no transplantation assurance. Fast symlink selection subtracts the validated external xattr sector allocation. Scope/generation, native names, deferred positional reads, shared budgets and caller-stability requirements remain the same.
