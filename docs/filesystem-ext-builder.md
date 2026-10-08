# Direct classic ext2 new-image builder

`fs_ext_builder::ExtBuildPlan` authors an unpublished new image directly. It does
not invoke mkfs or edit an existing filesystem. The caller owns exclusive target
storage and source stability through planning, emission and verification. No
publication, firmware, existing-image editing or power-loss guarantee is implied.

The explicit profile is Linux revision 1, 128-byte inodes, 1/2/4 KiB blocks,
32-byte group descriptors, `filetype` and `sparse_super` only. Groups contain
allocation bitmaps and inode tables; primary and sparse backup superblocks and
descriptor tables agree. Inodes 1–10 are reserved, root is inode 2, and ordinary
objects start at inode 11. There is no implicit lost+found; callers may supply an
ordinary directory with that name. Journal, xattrs, ACLs, extents, checksums,
special objects, symlinks, resize reservations and files larger than signed
32-bit lengths are outside this profile. Classic direct/single/double/triple
indirect maps are encoded; the native gate exercises direct, single and double
maps, not triple maps.

Objects and namespace links are separate inputs. Define each scoped `ObjectId`
once in `ExtBuildObject`. `ExtBuildLink` names that object under an optional
directory identity, with `None` denoting root. Repeated regular object links share
one inode and payload allocation, preserving that explicitly supplied hardlink
relationship. Directory aliases, disconnected objects, cycles, duplicate exact
byte names, missing parents and parents that are regular files fail preflight.
Names remain exact bytes, including non-UTF-8 bytes; slash, NUL, empty, dot and
dot-dot names are rejected. Siblings sort by unsigned native bytes. Objects sort
by complete scoped identity, making allocation independent of input order for
the same identities. Dot/dot-dot references and directory/file link counts are
authored explicitly, with a classic maximum of 32000 links.

`ExtBuildMetadata` is a required transformation policy: caller-selected file and
directory permissions, full Linux UID/GID and seconds for access/modification/
change timestamps. It does not preserve source metadata. UUID is explicit.
Payloads remain deferred through `Arc<dyn ReadAt>` or `Arc<dyn FileRead>`;
indexed short reads are completed with bounded scratch. Logical sparse or
unwritten zeros are materialized into initialized data blocks, and the report
states this allocation transformation. The builder does not inspect or preserve
source extent allocation. Source lengths and indexed source identities are
rechecked before emission and after full regeneration; this cannot detect an
unobserved concurrent change, so the caller's stability contract is essential.

Geometry, inode capacity, complete allocation, namespace and independent object,
link, name-capacity, volume-block, work and depth limits are checked before any
target write. A retained shared-budget lease covers indexed block maps, inode
tables, directories, indirect blocks and planning scratch; payload and whole
image buffers are absent. Vec/hash allocations are fallible, sorting uses no
heap scratch, and cancellation is checked through planning and each bounded
render/write operation. Bitmap tail bits are occupied. Every output byte,
including boot padding, unused inode slots, free blocks and file tails, is
initialized. Emission supports short writes, calls one actual flush, then reads
and compares every byte against fresh regeneration and verifies whole-image
SHA-256. A failed flush reports `UncertainDurability`; errors after an attempted
write report `InterruptedWrite` while retaining the causal error. Length changes
observed before mutation report `StalePlan`.

The layout follows the primary [Linux ext2 documentation](https://www.kernel.org/doc/html/latest/filesystems/ext2.html)
and the shared classic field definitions in the kernel's
[superblock](https://www.kernel.org/doc/html/latest/filesystems/ext4/super.html),
[inode](https://www.kernel.org/doc/html/latest/filesystems/ext4/inodes.html) and
[directory entry](https://www.kernel.org/doc/html/latest/filesystems/ext4/directory.html)
references. Newer ext4 feature encodings from those references are excluded.

Portable tests cover complete reader/audit acceptance for all three block sizes,
multiple groups and backups, nested/native non-UTF-8 names, hardlinked inodes,
350123-byte indexed payloads, deterministic reordered inputs, explicit Linux
metadata, sparse logical materialization, short reads/writes, cancellation,
stale source lengths, write/flush/readback faults, space/collision/connectivity
preflight and budget refunds.

The explicitly enabled native gate requires tools and an evidence directory;
missing tools fail the gate. Run:

```sh
EXT_BUILDER_EVIDENCE=/data/cache/partmgr-ext-builder-evidence \
  cargo test --locked --test fs_ext_builder \
  --target-dir /data/cache/partmgr-ext-builder-target \
  native_e2fsck_debugfs_direct_builder -- --ignored --nocapture
```

The `classic-ext2-direct-builder-v1` receipt retains exact native argv, tool
versions/resolved binary hashes, source/test/manifest/lockfile/test-binary hashes,
whole-image/payload hashes and native diagnostics. Eight images compare identical
across reversed inputs: 16/32 MiB at 1 KiB, 16 MiB at 2 KiB and 32 MiB at 4 KiB,
with 4096 blocks/group. `e2fsck -f -n` checks each without repairing it. Debugfs
extracts the nested payload independently, compares exact bytes, reports both
names at inode 12 with two links and displays the non-UTF-8 name bytes. The 1 KiB
payload crosses the double-indirect boundary. All images also reopen through
`ExtVolume` and pass its complete ownership/namespace audit. The receipt at
`/data/cache/partmgr-ext-builder-evidence/classic-ext2-direct-builder-v1.txt`
records e2fsprogs 1.47.4 acceptance. Modeled I/O faults and actual flushes do not
establish physical power-loss behavior or boot compatibility.
