# Immutable XFS v5 baseline

`fs_xfs::XfsVolume`, `fs_xfs_audit::audit` and `fs_xfs_tree::XfsTreeSource`
provide a strict reader, complete audit for its supported profile and common
deferred tree access. No mounting, replay, repair, editing, publication or
discard authority is implemented.

The explicit profile is **xfs-v5-leaf-inline-shortform-fresh-log-v1**: single
data device, 4096-byte blocks, 512-byte sectors and 512-byte v3 inodes. It accepts
`versionnum=0xb4a5`, `features2=bad_features2=0x18a`, incompatibility mask `ftype`
and zero other extension masks. It rejects finobt, sparse inode chunks, rmapbt,
reflink, bigtime, large extent counts, parent pointers, exchange range, metadata
directories, realtime devices, quotas, external logs, metadata UUID remapping,
ASCII case-insensitive names, stripe geometry and unknown extensions.

AG free-space and dense inode btrees must be single leaves with checked CRC32C,
magic, UUID, physical block number, AG owner, record count and null siblings.
Bnobt/cntbt extent sets and key orderings, AG free counts and longest extents
agree. AGFL rings and active entries are bounded. Dense 64-inode chunk records,
free masks, AGI and primary inode counters agree. Inodes carry CRC32C, physical
identity, UUID and generation. Regular files use inline extent records;
directories use shortform records. Multi-level AG trees, bmap-btree forks,
block/leaf/node directories, attribute forks, symlinks and special objects are
explicitly unsupported. Empty realtime bitmap/summary inodes remain protected
system objects even without a realtime device.

The log gate accepts the exact formatter's initial v2 clean-unmount record:
cycle/LSN 1, little-endian unmount item, formatter zero-CRC header, matching UUID
and zero remaining log sectors. It scans the entire bounded internal log with
fixed scratch. All indexed metadata LSNs must be zero. Historical logs, including
ordinary mounted clean logs, are **unsupported**; no general log checksum/replay
or clean-state inference from an arbitrary unmount marker is claimed. Secondary
superblocks retain native stale root/system inode, in-progress and lazy summary
fields; checksummed static geometry, UUID and feature facts must agree.

Extent records preserve logical positions, written/unwritten state and physical
AG addresses. Logical overlap, boundary crossing and signed-file-size overflow
fail. Stored block counts include all allocation, including beyond logical EOF.
Opening streams rejects metadata/log/free-space aliases. Indexed sparse gaps and
unwritten ranges return zeros without payload source reads; the audit still
accounts for their allocation. Deferred files retain original source context,
shared resource leases and both cancellation contexts after volume/tree drop.
Even zero-only reads check source length. Causal backend errors remain attached.
`CallerGuaranteedStable` is required: length checks are not snapshots or byte
change detection.

Names remain exact bytes, including non-UTF-8, with exact comparison. Shortform
parents, entry offsets and i8count are checked. Duplicate names fail decoding.
Tree inventory rejects directory aliases/cycles, wrong parents, wrong-type or
unallocated references and user names pointing at system inodes. Hardlinked
regular names share scoped inode identity and generation. Pagination tokens are
scoped to source, generation and directory. UID/GID, mode and nanosecond native
times are exposed; exact checksummed inode bytes retain project IDs, ctime and
other facts as an opaque metadata attribute. Metadata transplantation is not
implemented. ACL/security fields are absent because attribute forks are excluded.

The complete audit accounts for AG headers, both free trees, inode trees, active
AGFL blocks, every allocated inode chunk, the internal log and all file extents.
It detects crosslinks, referenced-free blocks, lost allocations, unreachable
inodes, invalid references, directory topology/link-count defects and primary
free-block summary disagreement. Primary free summaries include AGFL; returned
free ranges describe bnobt/cntbt extents and exclude active AGFL reservations.
Free ranges are suppressed for every defect. Unsupported profiles, work,
finding or memory exhaustion return errors without partial clean reports.
An immutable clean audit never authorizes discard or writes.

Reader limits cap AGs, allocated inode slots, metadata/extent records, work and
scanned log bytes. Inventory reservations use validated actual inode-slot counts
and cover all indexes and bounded scratch. Audit/tree leases add independent
block, finding, object, entry, work and depth bounds. Allocation is fallible and
cancellation is checked throughout. The implementation buffers neither the full
source nor file payload. A 400 MiB native image opens/audits/reads under a shared
32 MiB limit.

The primary reference is [XFS Algorithms & Data Structures](https://cdn.kernel.org/pub/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf),
edition 3, revision **3.14159265358 (April 2025)**, SHA-256
`f2549bc83b8ddfeb629412b7a1f1381bf0f5c21feb224c949040ff68e547396a`.
It is archived at `/data/cache/partmgr-xfs-profile/xfs-filesystem-structure.pdf`.
Primary kernel [format declarations](https://github.com/torvalds/linux/blob/master/fs/xfs/libxfs/xfs_format.h)
and [log declarations](https://github.com/torvalds/linux/blob/master/fs/xfs/libxfs/xfs_log_format.h)
are archived alongside it with exact hashes. Native acceptance is separate from
this specification review; supplying `XFS_SPEC_ARCHIVE` copies these references
into the evidence bundle and records their hashes.

Six portable tests use `tests/fixtures/xfs_clean.rs::xfs_seed`, a pure independent
four-AG 1 MiB structure with no production codec imports. They check CRC,
sparse/unwritten zero/no-read semantics, payload boundaries, hardlinks, native
metadata, allocation-identical name/topology defects, crosslinks/lost allocation,
scoped pages, causal errors, both cancellation contexts, stale lengths,
work/memory caps and lease refunds. The compact structure is not claimed to meet
native mkfs minimum-size/log recommendations; native fixtures establish that
separate evidence.

Run the explicitly enabled native gate (missing required tools fail):

```sh
XFS_TOOLS=/nix/store/v095x2333glq7pwmr7mib6d2lx28gmv0-xfsprogs-6.19.0-bin/bin \
XFS_SPEC_ARCHIVE=/data/cache/partmgr-xfs-profile \
XFS_EVIDENCE=/data/cache/partmgr-xfs-evidence \
cargo test --all-features --locked --test fs_xfs_native \
  --target-dir /data/cache/partmgr-xfs-target -- --ignored --nocapture
```

Xfsprogs **6.19.0** independently generates a four-AG 400 MiB prototype with
nested 350123-byte payload and a 64 MiB log, explicitly disabling excluded
defaults. Independent fixture patches create a leading sparse hole, allocated
unwritten extent and hardlinks including native bytes `x FF`. `xfs_repair -n`
accepts all four; `xfs_db -r rdump -s` recovers exact payloads and names into
fresh evidence directories. Framework reopen/full audit/tree and random reads
agree. Both checkers reject a modeled metadata crosslink; framework free ranges
are empty. Source hashes prove native read-only commands leave images unchanged.
A raw wrapper adds 8192-byte prefix and 4096-byte suffix; a bounded DiskView at
offset 8192 reads/audits the image with fixed shared memory and unchanged framing.
No QCOW/container, mount/replay, firmware or writable XFS acceptance is claimed.

The final receipt is
`/data/cache/partmgr-xfs-evidence/xfs-v5-leaf-inline-shortform-v1.txt`: exact
argv, tool versions/binary hashes, specification/source/fixture hashes,
image/payload hashes and native metadata/log diagnostics. Ordinary mounted clean
logs, larger directory forms, multi-level allocation/file trees, extended
metadata and additional feature profiles remain explicit acceptance gaps.
