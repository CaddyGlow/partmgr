# Classic ext2 growth within the final group

`ExtEditor::plan_grow_filesystem` plans native filesystem growth in an already
large enough owned region. It returns an `ExtEditBatch` and an
`ExtFilesystemGrowReport`. Only the batch carries session and generation
authorization; the report describes the proposed geometry.

The initial profile accepts classic ext2 with 128-byte inodes and 1, 2 or 4 KiB
blocks. Compatible features must be empty; only `FILETYPE` and `SPARSE_SUPER`
are admitted in their respective feature words. Growth must remain in the
existing final block group. New groups, inode tables, metadata relocation,
journaled ext profiles and backend or partition resizing require separate work.
The caller must maintain exclusive access and establish that the external undo
journal is disjoint from the target.

Planning performs fresh geometry and complete ownership checks, clears only the
newly admitted block bitmap tail, and updates primary and existing backup
geometry and free counters. Reserved blocks retain their absolute count.
Backup free counters become the new primary-derived totals, including when old
dynamic backup counters were stale. Each copy retains its own original bytes
for undo; unrelated fields, backup group numbers and existing payload remain
unchanged. Newly free blocks retain their old bytes until ordinary allocation
initializes them.

Memory, affected-byte, patch, undo-body and work limits are finite. Every
projected patch comparison consumes planning work and checks cancellation.
The two complete audits also use their explicit audit limits. Planning performs
no target or journal writes. Expected bytes and generation are checked again by
the existing external undo commit protocol.

Commit uses the native dirty fence, staged writes, durable readback and complete
grown ownership audit before publishing the clean state. It refreshes cached
geometry before returning the session to `Ready`. A failure after the undo
commit marker still leaves `NeedsRecovery`; recovery must inspect that marker
and reopen the actual geometry. Old file handles are invalidated by commit.

## Qualification status

Seven independent host tests pass, including four-group sparse and non-sparse
profiles at each block size, stale backup counters, zero-write limit failures,
stale batches, committed-marker recovery and allocation into the admitted tail.
The separate cut matrix passes 6,144 cases. Each block size observes 48 writes,
nine flushes and 151 reads during its successful commit baseline. Errors and
cancellation at each boundary, torn write prefixes, immediate and volatile
persistence, and either failed-flush outcome cold-recover to the exact original
or committed container bytes according to the durable undo marker.

Formatting, all-target/all-feature Clippy and tests, no-default-feature Clippy
and portable tests pass with unchanged source snapshots. Logs and source are
retained at
`/data/cache/partmgr-maintenance-ext-grow-checks-20261011-v2/result.json`.
The release-mode production gate passes on the three independently populated
native images. Its 43 commands include the Rust gate and read-only e2fsprogs
checks. The verifier independently reconstructs every permitted changed byte,
compares native `resize2fs` bitmap and counter results, checks all outside bytes,
and compares complete payloads, hardlinks and inode metadata. Missing source,
reused evidence, stale compiled source and an altered verifier all reject.
The release profile, source, tools, inputs and executable are bound in
`/data/cache/partmgr-ext-grow-release-binding-20261011-v1/result.json`;
its native receipt is `positive/qualification.json` beneath that directory.
All 515 indexed envelope artifact hashes were independently rechecked.
The independent native reference corpus is retained at
`/data/cache/partmgr-ext2-grow-oracle-20261011-v5/receipt.json`.
It includes populated two-group filesystems at all three block sizes and
native `resize2fs` references, with exact free-space deltas and unchanged file
contents, hardlinks and native metadata.

Native `resize2fs` truncates a regular-file backing to filesystem size. The
reference corpus therefore retains its raw resized output and separately
assembles that native filesystem region into a clone of the extended backing
for bounded-region comparison. It does not claim that `resize2fs` preserves
bytes outside its filesystem. Kernel mounts, physical crash durability,
ext3/ext4 growth and creation of new groups remain separate gates. Allocation
into newly admitted space has host evidence above; native allocation after
growth and native crash recovery are not established by this offline gate.
