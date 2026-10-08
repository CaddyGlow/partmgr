# Whole-volume classic ext2 audit

`fs_ext_audit::audit` is an explicit read-only whole-volume operation over an
already opened `ExtVolume`. Ordinary direct reads and `ExtTreeSource` inventory
remain separate; successfully opening a file does not establish allocation
consistency. The caller must keep backing bytes immutable throughout the audit.
The report grants no write authority, source isolation, exclusive access, durable
commit, or firmware evidence.

The audit retains the reader's strict clean Linux/classic ext2 feature allowlist.
Its additional inode profile supports regular files, directories, and standard
reserved slots 1–10 with no allocations (root inode 2 is inspected normally).
The standard first ordinary inode is 11. Timestamps in the empty bad-block inode
are permitted, as independently emitted by mke2fs; nonempty bad-block lists and
other reserved-inode allocations are explicitly unsupported. Allocated symlinks,
devices, sockets/FIFOs, nonzero inode flags, external xattrs, high size words,
fragments, journals, recovery-required states and advanced feature sets are not
silently interpreted. Unsupported states return a typed `Unsupported` error;
budget, cancellation and underlying I/O failures return errors without any clean
report.

The complete passes establish:

- Every block/inode bitmap is decoded, including out-of-range tail bits. Counts
  are compared with group descriptors and the primary superblock.
- Superblock/descriptor copies, both bitmaps, and full inode tables are claimed
  as filesystem metadata. Unallocated metadata blocks are defects. Static backup
  geometry, feature fields and UUID are compared with the primary; backup group
  descriptor metadata pointers must agree. Mutable backup free counts and mount
  history are deliberately excluded because they can be stale after native tools
  update the primary.
- Every allocated ordinary inode is inspected, including objects unreachable
  from root. All fifteen classic pointers and every allocated indirect subtree
  are examined, including pointers beyond EOF. Direct, single, double and triple
  indirect trees are bounded to three levels. Cross-file sharing, repeated
  pointers, data/metadata aliases, cycles, out-of-range/free references and
  beyond-EOF allocations produce findings. Complete nonaliased maps are checked
  against the inode's 512-byte sector count, including indirect metadata blocks.
- Every allocated directory is decoded. Free/out-of-range/reserved inode
  references and record-type disagreements are diagnosed. Reference counts
  include dot/dot-dot and all allocated directories, not just root-reachable
  ones. Dot topology is checked even for disconnected directories. Root traversal
  checks parent relationships, rejects directory aliases/cycles and identifies
  unreachable allocated inodes. Native hard-linked file names count separately
  against one inode's recorded link count.
- Allocated blocks with no metadata or inode owner are lost allocations. Free
  ranges contain only unallocated, unclaimed data blocks and are exposed only
  when **all** audit passes are complete and the entire finding list is empty.

If malformed directory storage prevents decoding, the report records
`InvalidDirectory` and `namespace_complete()` is false. Global link-count and
reachability assertions are then withheld; bitmap and block-map accounting still
runs. A successfully decoded directory containing an invalid reference remains
a completed decode with an explicit defect. Findings never stop the remaining
passes unless the caller's diagnostic limit is exhausted. Directory topology and
allocation correctness remain independently visible in the report.

`ExtAuditLimits` bounds declared blocks/inodes, aggregate directory logical blocks,
aggregate directory references, decoded work units and retained findings. Work
units cover bitmap bits, inode/pointer slots, descriptor comparisons, metadata
claims, namespace edges and final block accounting. Geometry limits also bound
fixed scans outside those units. Indirect blocks are decoded once per successful
unique claim, and aliases are not expanded recursively. Per-inode directory edge
ranges avoid rescanning the entire graph for each traversed directory. Name
uniqueness checking remains the bounded strict directory decoder's comparison
cost; no broad linear-time or random-read benchmark claim is made.

The shared `Resources` pool reserves a conservative upper bound before fallible
allocation: 48 bytes per volume block, 128 bytes per inode slot including slot
zero, 32 bytes per possible directory reference, the exact finding-record size
per allowed finding, and 32 KiB for fixed scratch/stack buffers. This covers
ownership maps, allocation flags, inode facts, graph/index/traversal state, free
ranges and findings. Strict directory decode and indexed handles retain their own
reservations from the same pool. The report retains its reservation until drop;
exhaustion and failures refund it. Cancellation is checked throughout metadata
reads and bounded work. The original I/O cause remains attached to I/O errors.

Independent tests assemble raw ext2 structures without a production builder.
They verify a clean hard-link image and exact free range; lost/cross-linked/free
blocks; indirect cycles; maps beyond EOF; sector/link/free-counter defects;
invalid directory references/types/topology; malformed decode completeness;
bitmap tails; resource/work/finding limits; cancellation during scanning; retained
I/O causes; and reservation refunds. A 64 KiB sparse fixture with a logical file
larger than 64 MiB exercises triple-indirect ownership without allocating or
reading payload-sized buffers.

Native evidence uses a fresh 16 MiB regular-file image:

```text
mke2fs -q -F -t ext2 -b 1024 -O none -I 128 <image>
debugfs -w -f <script> <image>
e2fsck -fn <image>
```

The debugfs script writes an independently generated 400,003-byte file, adds a
hard-link alias, and sets the native link count to 2. This crosses direct,
single-indirect and double-indirect mappings and uses two block groups with a
backup superblock/GDT. The audit and `e2fsck -fn` both pass; an exact byte comparison
confirms the check leaves the fixture unchanged. Separate retained corrupt images verify backup geometry and descriptor-pointer
diagnostics. The native test is an explicit `#[ignore]` interoperability gate,
which normal host checks do not execute. Enabling it requires an absolute
`PARTMGR_EXT_AUDIT_EVIDENCE` destination and all three native tools; missing tools
or native command failures fail the gate rather than silently pass. All tools
were available at e2fsprogs/EXT2FS version 1.47.4 and the enabled gate passed on
2026-10-07.

Focused verification:

```sh
cargo test --locked --test fs_ext_audit
cargo clippy --test fs_ext_audit --locked -- -D warnings
PARTMGR_EXT_AUDIT_EVIDENCE=/data/cache/partmgr-filesystem-ext-audit-evidence \
  cargo test --locked --test fs_ext_audit \
  native_mke2fs_debugfs_full_audit_with_backups -- --ignored --exact --nocapture
```

The retained gate directory contains the clean image, deterministic payload,
authoring script, both corrupted backup controls, audit diagnostic outputs, and
all native stdout/stderr. `evidence.json` records exact executable paths/argument
arrays, executable hashes, version command outputs, exit codes, output hashes,
compiled reader/audit/core/index/test and lockfile hashes, audit limits/results,
and source payload/image hashes before and after the read-only native check.
Artifacts and the receipt are fsynced, along with their containing directories.
Failed gates cannot write a passed receipt; completed command records remain
available beside the initial gate-start record for failure diagnosis.

Verified retained receipt:
[`1791407955-160569060-192/evidence.json`](/data/cache/partmgr-filesystem-ext-audit-evidence/1791407955-160569060-192/evidence.json).
It establishes 3 ordinary allocated inodes, 407 uniquely owned inode blocks,
2 audited free ranges, no findings, and unchanged image SHA-256
`f536a3d62e075e8f41b19717ec0c6345a7d4df976a1289cea6e9063f90e65f83`.
Receipt JSON and all recorded tool-output, source, script, payload and image hashes
were independently rechecked after the gate run.
An enabled-gate negative control with an empty tool search path returned exit 101
and produced no passed receipt; see
[`missingtools-control.json`](/data/cache/partmgr-filesystem-ext-audit-missingtools-evidence/missingtools-control.json).

Native compatibility covers this declared classic profile. It does not establish
ext3/4 recovery, special-object payload decoding, metadata-preserving capture,
servicing correctness, or QEMU/OVMF firmware boot behavior.

The immutable audit additionally accepts the [explicit ext3/ext4 profiles](filesystem-ext-profiles.md): extent metadata/data/unwritten preallocation (including beyond EOF) and inactive internal journal allocation are fully included in ownership/sector accounting. Existing classic mutable-storage auditing remains classic-only. Unsupported checksum, descriptor, inode and journal/recovery features return errors rather than a clean report. The classic native receipt above remains bound to its historical source snapshot.

The bounded modern [ext4 profile](filesystem-ext-profiles.md) additionally validates normalized uninitialized allocation maps, global flex metadata exclusions, metadata/inode/extent/directory/orphan/xattr CRCs, and backup superblock/descriptor checksums. Canonical hidden resize references may share only the independently validated reserved-GDT metadata; its normal double-indirect block is claimed once. Every initialized orphan-file block is owned, empty and checksum-bound to its physical location. External xattr sharing is restricted to its metadata role, requires exact actual/native reference counts, and is included in every referencing inode's sector count while physical ownership is counted once. Indexed directories with the native DIR_NLINK sentinel retain complete topology/reference accounting without treating the sentinel as an exact numerical count. Reserved unsupported objects and special inode kinds remain explicit audit gates.
