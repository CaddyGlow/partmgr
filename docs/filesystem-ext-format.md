# Fresh classic ext2 working images

The `fs_maintenance_format` adapter integrates the classic ext2 builder with an
owned formatting session. Its initial profile creates an empty root directory
with explicit UUID, block geometry, ownership, permissions and timestamps. It
does not implement the planned ext3/ext4 format profiles, repair or expansion.
The adapter has scoped host fault and e2fsprogs evidence below; builder receipts
alone do not qualify it.

`ExtFormatImage::create_new` takes an absolute working pathname and creates it
exclusively. Existing files and symlinks are rejected without truncation. The
caller must exclusively control the working file and directory throughout the
session. Exclusive creation prevents replacing an existing path; it does not
prevent another process opening the new file. Use a private working directory
when an incomplete image must remain inaccessible to consumers.

`plan_empty` borrows the owner exclusively, validates the builder profile and
resource limits, and constructs the layout without writing payload bytes. The
borrow prevents switching files or extracting the owner while a plan exists.
Dropping an unused plan permits planning again. Creating and sizing the working
file are separate, earlier filesystem mutations; planning does not undo them.

Emission rechecks the actual file length and scans the whole bounded output for
zero bytes before the first payload write. The existing builder writes, flushes
and verifies the complete image. The adapter then runs the allocation and
namespace audit and checks actual superblock UUID, features and geometry.
Its report retains the full-image digest and audit alongside native fields; it
does not invent a persistent backend identity from a pathname or file length.

Any emission error makes the session terminal. Before any payload write attempt,
the original failure category is retained. After a write attempt, an interrupted
write retains its original error in the cause chain; failed durability barriers
remain `UncertainDurability`. The incomplete working file is retained for
inspection, and the session cannot retry or yield a verified artifact.

Only successful emission enables `into_verified`, which transfers the working
file and pathname to the caller. This is separate from publication: the adapter
does not rename the file, replace existing output, or establish directory
durability. Publication requires the caller's explicit durable output protocol.

Finite builder, audit, memory and zero-scan limits apply. Cancellation is checked
before creation and between bounded emission units. Source-owned plans cannot
authorize an existing device, arbitrary `Storage`, partition region or live
filesystem. Those operations require separate ownership and recovery contracts.

## Scoped qualification

Eleven private tests include 1,260 independent interruption cases on 1 MiB images
at each supported block size. Successful baselines observe 16 writes, one flush
and 72 reads, including zero scan, byte verification, audit and final inspection.
Every boundary is exercised with I/O failure or cancellation, with partial writes
and immediate or volatile persistence. Assertions compare actual visible and
durable prefixes, preserve original causes and deny reuse of failed sessions.
The focused log is
`/data/cache/partmgr-ext-format-focused-20261011-v1.log`.

The release-mode native adapter gate generated three empty 16 MiB images.
e2fsprogs 1.47.4 checked them without repair; debugfs independently confirmed
geometry, UUID, features, free counts, root metadata and the complete namespace.
Images remained unchanged by these commands. Missing source/tool, reused output,
stale compiled source and altered verifier controls all failed. The 703 retained
artifact hashes were rechecked without mismatch. Receipts bind source, executable,
tools and images at
`/data/cache/partmgr-ext-format-native-20261011-v2/qualification.json` and the
release build binding at
`/data/cache/partmgr-ext-format-release-binding-20261011-v2/result.json`.
Formatting, all-target/all-feature Clippy and tests, no-default-feature Clippy
and portable host tests passed with unchanged source snapshots. Logs and the
compiled-source archive are indexed by
`/data/cache/partmgr-maintenance-ext-format-checks-20261011-v2/result.json`.

The receipt records single release-mode formatting timings including file
creation, sizing, zero scan, emission, file flush, verification and audit.
Cache state and competing host work were uncontrolled; these timings do not
close the planned cold-cache or broader workload benchmark gates. Native mounted edits, crash
recovery and publication durability remain separate qualification work.
