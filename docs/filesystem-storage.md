# Filesystem storage foundation

`fs_storage::BoundedSession<S: Storage>` owns its backend and retains the
backend's lock. It exposes fixed bounded byte geometry, positional reads and
short writes, constant-scratch zeroing, and explicit flush. It does not expose
the backend, resizing, snapshot management, or discard. Bounds are checked for
the entire zero request before mutation. Errors from writes and flush retain
`UncertainMutation`, and uncertainty is sticky even after subsequent flush.
Successful flush delegates the backend's existing medium durability promise;
publication-directory durability is a separate orchestration step.

`SectorGeometry` records known logical and physical sizes separately. Unknown
values remain unknown. Neither sector size implies filesystem block size or
atomic sector writes. Callers must enforce external exclusivity and immutable
backing parents; advisory file locks do not exclude mounted access or writers
that ignore locks.

`ImmutableRegion` reuses `virtdisk::DiskView`: it retains its immutable source,
source context, partition annotation, and shared read budget. It is separate
from mutable sessions, which do not implement immutable `ReadAt`.

## R4 dependency release gate

The root dependency is now published crates.io virtdisk **0.2.0**, including
ImageWriter, WriteAt and InspectImage. `fs_storage::ImageWriterSession` owns the
actual writer privately and checks its handle capabilities and geometry. The
standalone `integration/storage` package re-exports this adapter and validates it
as a consumer, using only the new partmgr API checkout override. See
[writer bridge evidence](filesystem-writer-bridge.md) for the registry checksum,
raw/QCOW2 tests and independent conversion receipt. No sibling dependency is
required by the root manifest.

The previous portable wasm reader gate now fails on virtdisk 0.2.0's unconditional
entropy dependency. That release regression has a concrete sibling refactoring
plan. Native availability does not close portable, performance, wider backend or
filesystem recovery gates. The following sketch illustrates the private bridge;
the actual tested public entry point is `ImageWriterSession::new`.

```rust,ignore
use std::io;
use partmgr::{fs_storage::{BoundedSession, SectorGeometry}, storage::Storage};
use virtdisk::{Capability, ImageOperation, ImageWriter, InspectImage, WriteAt};

struct WriterStorage(ImageWriter);
impl Storage for WriterStorage {
    fn len(&self) -> io::Result<u64> { Ok(WriteAt::len(&self.0)) }
    fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(offset, out)
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        self.0.write_all_at(offset, bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { WriteAt::flush(&self.0) }
}
fn session(writer: ImageWriter, start: u64, length: u64)
    -> io::Result<BoundedSession<impl Storage>>
{
    let facts = writer.inspection();
    for operation in [ImageOperation::Read, ImageOperation::Write, ImageOperation::Flush] {
        if facts.capabilities.get(operation) != Capability::Supported {
            return Err(io::ErrorKind::Unsupported.into());
        }
    }
    let geometry = SectorGeometry::new(
        facts.geometry.logical_sector_size,
        facts.geometry.physical_sector_size,
    )?;
    BoundedSession::new(WriterStorage(writer), start, length, geometry)
}
```

`write_all_at` success becomes a full-length `Storage::write_at` result; failures
propagate without inventing a partial count and the enclosing session records
uncertainty. Inspection and capabilities come from the handle, not the family.
The owned bridge is now implemented in `ImageWriterSession` and compiled
against published virtdisk0.2.0. Registry consumer tests cover raw/QCOW2,
read-after-write and retained locks; modeled partial writes and failed flushes
remain separate from actual backend power-loss evidence. Preserve the published compatibility read APIs and
separately measure performance before declaring the backend sufficient.

## Existing FAT edits through raw and QCOW2 sessions

`integration/storage/tests/fat_edit.rs` supplies a hand-authored fragmented FAT12
volume at8192 inside a2MiB logical disk. The complete container writer is acquired
privately by `ImageWriterSession`, narrowed to the exact65536-byte volume, then
owned by `FatEditor` with a separate locked regular-file external undo journal.
The test performs a cross-cluster replacement,700-byte extension and truncation
to513bytes, checks lock retention and invalidation of old handles after each
commit, and reopens through the immutable reader plus complete ownership audit.
The entire reopened logical disk must equal only the reviewed patches; unrelated
volume bytes and container framing remain unchanged. Shared reservations refund.

Both ordinary raw and Linux QCOW2 tests pass. The independently enabled gate runs
`qemu-img check` and raw conversion after the filesystem edits, compares every
converted logical byte with the reviewed expected disk, and verifies the QCOW2
source is unchanged by the oracle. This is container and adapter evidence; the
separate fsck/mtools FAT editor matrices establish native filesystem acceptance.
The gate does not claim filesystem-native validation of its tiny handcrafted
fixture, process-kill/power-loss behavior, device editing or firmware success.

```sh
PARTMGR_FAT_CONTAINER_EVIDENCE=/data/cache/partmgr-fat-container-new \
  cargo test --manifest-path integration/storage/Cargo.toml --locked \
  --config 'patch.crates-io.partmgr.path="/home/rick/projects-caddy/partmgr"' \
  --test fat_edit independent_qcow2_conversion_after_fat_replace_extend_truncate \
  -- --ignored --nocapture
```

The only development override above is partmgr; virtdisk resolves from crates.io.
Successful evidence: `/data/cache/partmgr-fat-container-edit-20261008/fat-qcow2-m67MNE/evidence.txt`.
Missing-tool/environment controls with the same binary fail101 without a passed
receipt: `/data/cache/partmgr-fat-container-negative-j_k6xnfp/control.json`.
Exact tool versions, argv, source/lock/test-binary and image hashes are retained.

## Owned exFAT edits through raw and QCOW2

`integration/storage/tests/exfat_edit.rs` runs replacement across the valid-data
boundary, zero extension and truncation through an exclusively owned bounded
WriterSession and physically separate locked undo file. Both raw and QCOW2 tests
pass. They check retained locks, stale handles, exact initialized payload bytes,
whole-disk equality with the reviewed final patches, unchanged prefix/suffix,
reopened immutable complete ownership audit and resource refunds. The 2MiB
specification fixture is independent of production builders; this gate establishes
container interoperability, not native exFAT tool acceptance or power-loss behavior.

```sh
cargo test --manifest-path integration/storage/Cargo.toml --locked \
  --config 'patch.crates-io.partmgr.path="/home/rick/projects-caddy/partmgr"' \
  --target-dir /data/cache/partmgr-filesystem-target/storage --test exfat_edit
```

Only partmgr is patched for development testing. virtdisk resolves as 0.2.0
from crates.io. The fixture, journal and comparison buffers belong to the test;
the filesystem resource pool is 8MiB and the undo body ceiling is 128KiB.

Owned classic ext2 replacement is exercised through both raw and QCOW2
WriterSession backends in `integration/storage/tests/ext_edit.rs`. A 64 KiB
independent volume is bounded inside a 4 MiB logical disk with an 8192-byte
prefix and distinct trailing framing. The tests enforce container/journal locks,
review exact expected/replacement patches, reject stale file handles after commit,
observe the new bytes through a second hardlinked native name, and compare the
entire reopened logical disk with the reviewed result. These host tests do not
substitute for independent native container/filesystem or firmware gates.

The ext2 container regression also extends a hardlinked file by 13,319 bytes
through a source returning at most 13 bytes per read, crossing into the single
indirect map. It then truncates to 513 bytes, asserting one indirect block is
allocated and subsequently freed. Each transaction verifies the full patch
before-image and updates the expected entire logical disk, checks stale handles,
and reads the new payload through the second native name. Final raw/QCOW2 reopen
must match every reviewed byte, including unrelated framing.

The ext2 raw/QCOW2 tests also create a 700-byte file under an exact non-UTF-8
native name with explicit mode metadata. They review every namespace/allocation
patch before commit, reject use of the pre-commit parent directory handle, read
back all created bytes and include the namespace transaction in the final entire
logical-disk comparison. This tests owned namespace creation through the actual
container session; native filesystem and recovery fault gates remain separate.

Ext2 container namespace coverage additionally creates a directory, moves the
new native-byte file into it and verifies the old name disappears and all moved
payload bytes remain exact. Unlinking the existing alias must preserve its shared
inode and content through the remaining hardlink. The final raw/QCOW2 image
comparison includes reviewed patches for every allocation, move and unlink.

The ext2 container sequence finally rejects deletion of the nonempty parent,
removes the moved file at its last native name and removes the resulting empty
directory. Reports must show inode release for both final removals, while the
earlier hardlink unlink must keep its inode. Caller-supplied nonzero deletion
times are explicit. Both removed paths must fail lookup; the final entire disk
comparison includes all nine transaction patch sets and unchanged framing.

After the complete ext2 editing sequence, the tests reopen the bounded volume
through the immutable ReadImage facade with RequireClean. Its complete allocation
and reference audit must pass, removed alias/directory names must be absent, and
the remaining native hardlink must yield all 513 bytes exactly. Reader/map leases
must refund after retained handles are dropped. This verifies engine reopening
through the actual containers; the independent e2fsprogs gate remains separate.

Ext2 raw/QCOW2 integration now injects an error after the first actual target
container flush completes. The test wrapper implements only mutable Storage and
preserves the underlying WriterSession lock. The editor must enter NeedsRecovery,
block the old file handle and recover through the real external FileStorage undo
journal. Full original payload readback and Ready state are required before the
nine successful transactions proceed. Final whole-disk equality includes the
recovered transaction's absence. This models a failed acknowledgement after a
real host barrier, not hardware power loss or container-level rollback.

The ignored Linux test
`independent_qcow2_conversion_after_ext2_recovery_and_namespace_lifecycle`
adds an independent container check after this complete sequence. Set
`PARTMGR_EXT_CONTAINER_EVIDENCE` to a fresh directory and run the test explicitly
with `--ignored`. It requires `qemu-img` and `sha256sum`, checks the QCOW2 image,
converts it to raw and compares every logical byte against the reviewed patch
model, including framing. The original container must remain unchanged by these
oracle operations. Its receipt records the executable, test source, dependency
lock, engine sources and tool hashes before work and revalidates them afterward;
the compiled test source must match its live source. Engine hashes are live
start/end evidence rather than embedded compiled-source assertions. Artifacts
are retained. Each oracle invocation uses the hashed tool path and retains its
argument vector, exit status, stdout and stderr, including unsuccessful runs.
This gate establishes independent container interpretation;
native filesystem interpretation remains the separate e2fsprogs gate.

The analogous ignored exFAT test
`independent_qcow2_conversion_after_exfat_replace_extend_truncate` uses a fresh
`PARTMGR_EXFAT_CONTAINER_EVIDENCE` directory. After bounded replacement, extension
and truncation, qemu-img must validate and convert the container; every converted
logical byte must match the reviewed patch model, including untouched framing.
Source/tool/executable revalidation and retained command/output evidence follow
the ext2 gate. This covers independent container interpretation, while the
exfatprogs filesystem oracle remains a separate gate.

The exFAT sequence also injects an error after the first actual target flush.
Its mutable-only Storage wrapper preserves the WriterSession lock. The editor
must retain the causal IO error, enter NeedsRecovery and reject the old file
handle; recovery through the external FileStorage journal must restore all
original payload bytes and Ready state before normal edits. The final disk model
includes the rejected transaction's absence. This is a failed acknowledgement
after a host barrier, without a hardware power-loss or container rollback claim.

## Partitioned APFS reads through converted QCOW2

`integration/storage/tests/apfs_read.rs` has an explicit Linux gate for the
64MiB authored APFS region at byte1048576 in a66MiB raw GPT/MBR disk. Set
`PARTMGR_APFS_CONTAINER_RAW` to the independently validated raw disk,
`PARTMGR_APFS_CONTAINER_IMAGES` to its directory containing `normal.qcow2` and
`compressed.qcow2` from `scripts/filesystem-container-check.py`, and
`PARTMGR_APFS_CONTAINER_EVIDENCE` to an absent evidence directory. Run the
`apfs_read` test explicitly with `--ignored`. Missing inputs fail the enabled
gate. It requires the explicit volume OID1026/native authored fixture profile.

The registry virtdisk reader compares every logical disk byte against the raw
reference before opening a bounded DiskView through ReadImage RequireClean.
After complete allocation audit, it opens the sparse data/resource fork and
drops the facade; retained handles must still return the entire independent
16397-byte model via73-byte requests and8-byte fork. Cancellation rejects even
empty EOF reads; all reservations refund after both handles drop. This checks
immutable container interpretation. Owned COW edits and container recovery need
separate evidence.

Frozen GPT and MBR acceptance receipts are respectively
`/data/cache/partmgr-apfs-gpt-container-facade-native-v2-0_vidunu/root-audit.json`
and `/data/cache/partmgr-apfs-mbr-container-facade-native-0_vidunu/root-audit.json`.
Each verifies both normal/compressed profiles and full retained payload models,
binds the consumer and partmgr snapshots, and references source/tool/log/hash
checks from the independent conversion receipt. The development-only partmgr
path patch targets its immutable snapshot; virtdisk0.2.0 remains registry-backed.
The isolated consumer uses explicit Cargo+1.99.0 because it is outside the
repository toolchain directory. Full consumer all-target strict Clippy passes
with the original integration/storage topology and referenced root fixtures.
The earlier flattened consumer copy failed all-target Clippy because those
fixture paths were missing; it remains failed evidence.
