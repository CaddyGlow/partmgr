# Initial immutable ext2 reader

`fs_ext` provides checked geometry, allocated inode inspection, classic direct /
single / double / triple indirect mapping into reusable `ExtentFile` handles,
sparse holes, and bounded directory inventory with native byte names. Returned
inode numbers preserve hard-link identity within the same volume. This is a direct
reader API; the separate [`ExtTreeSource`](filesystem-ext-tree.md) adapter
provides bounded complete inventory through the common `TreeSource` contract.
`ExtVolume::identity` returns source-scoped inode/generation identities;
`ExtFile` implements the common `FileRead` contract, including EOF and extent
visitation. The caller must keep the source immutable throughout deferred access; the reader
bounds all reads to the superblock-declared volume through `DiskView`.

The accepted profile has Linux creator encoding, revision 0 or 1, 1/2/4 KiB blocks,
128-byte inodes, clean state, classic per-group bitmaps and inode tables. Its
feature allowlist permits no compatible features, incompatible `filetype`, and
read-only-compatible `sparse_super` / `large_file`. High inode size words remain
unsupported, so individual files are limited to the low 32-bit size. All inode
flags, external xattrs, journals, dirty states, extent trees, metadata checksums,
64-bit descriptors, auxiliary devices, compression and encryption fail closed.
Feature acceptance is not an allocation-audit claim.

Group descriptor metadata ranges are checked for bounds and overlap. Inode and
block references must be allocated; data cannot alias bitmaps, inode tables,
superblock/descriptor copies, or indirect metadata observed while indexing that
file. Indirect paths are limited to three levels and reject cycles. Duplicate
payload blocks within one file are rejected. This does not audit cross-inode
ownership, lost allocations, full indirect subtrees beyond EOF, backup-superblock
agreement, inode block-count accounting, or directory topology / link counts.
Symlink targets, Unix metadata preservation and xattrs
remain future work; special inode data is never guessed as an ordinary stream.

Index construction has an explicit block-work limit and checked shared memory
reservations retained with handles. Directory inventory has explicit block and
entry limits, fallible allocations, retained accounting, and cancellation checks.
Each deferred read consults cancellation and uses its prebuilt index; no benchmark
or broad random-read performance claim is established here.

Independent tests assemble raw structures without a production builder, exercising
non-UTF-8 directory names, direct/single-indirect payload, sparse holes, feature
rejection, unallocated references, metadata alias cycles, cancellation and work
limits. The native fixture test generates a fresh regular-file image using
`mke2fs -q -F -t ext2 -O none -I 128` and adds a deterministic 130,123-byte
file with `debugfs -w -R "write <payload> /payload.bin"`. The reader resolves its
native directory name, repeats small reads across the direct/indirect boundary,
and compares a full SHA-256 digest with the original bytes. `e2fsck -fn` then
checks the fixture; an exact image comparison verifies no native-check mutation.
The test prints an explicit skip when any native tool is unavailable. All three
tools were available at e2fsprogs/EXT2FS library version 1.47.4 (6-Mar-2025),
and this test passed on 2026-10-07.
Native coverage establishes this payload profile, not complete
ext2 implementation or firmware correctness.

Layout references: Linux kernel documentation for
[block geometry](https://www.kernel.org/doc/html/latest/filesystems/ext4/blocks.html),
[inode encoding](https://www.kernel.org/doc/html/latest/filesystems/ext4/inodes.html),
and [directory records](https://www.kernel.org/doc/html/latest/filesystems/ext4/directory.html).
The implemented profile deliberately gates modern ext4 encodings described there.

The immutable engine also has explicit [ext3 inactive-journal and ext4 extent profiles](filesystem-ext-profiles.md). Their accepted features, bounded indexed maps and native evidence are separate from the classic reader evidence above. The immutable engine also accepts a bounded modern default profile with metadata checksums, flex groups, directory indexing and native xattrs; remaining features and evidence are documented there.
