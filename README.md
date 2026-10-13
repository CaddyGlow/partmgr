# partmgr

Lossless GPT and MBR inspection, owned layout editing, deterministic write plans,
and explicit recovery. Partition metadata, filesystem operations, payload copying,
and observed firmware boot have separate APIs and outcomes.

```toml
partmgr = "0.1.2"
```

```sh
cargo test --all-features --locked
```

Requires Rust 1.96 or newer. Dependencies resolve from crates.io; no sibling checkout is required. CI checks
formatting, Clippy and tests on Linux and Windows. Independent partition-tool and
QEMU/OVMF jobs provide additional format and firmware evidence.

The [refactoring benchmarks](docs/benchmarks.md) compare GPT edit batching,
FAT planning/emission, APFS metadata access, NTFS MFT loading/parsing and USN
record decoding in both library configurations.

## BitLocker

The optional `bitlocker` feature adds experimental read-only volume inspection,
recovery-password and clear-key unlocking, supplied-key access, and XTS-AES
decrypted readers. It supports the portable build and feeds the existing
filesystem APIs. The separate `bitlocker-write` feature adds owned ciphertext
transactions and external undo recovery. Envelope discovery is available without
either feature; decrypted views retain distinct provenance identities.
See [BitLocker support](docs/bitlocker.md) for the exact profile,
usage, native evidence, and remaining qualification gates. The opt-in
`bitlocker-tpm` feature adds experimental TPM 2.0 policy unsealing and isolated
swtpm state imports; see [provider support and limits](docs/bitlocker-tpm.md).

## Building without std

Disable the default `std` feature to build the entire library with `core` and
`alloc`, including every filesystem reader, builder and owned editor:

```toml
partmgr = { version = "0.1.2", default-features = false }
```

```sh
cargo build --no-default-features --locked
# With the target's core/alloc libraries installed:
cargo build --no-default-features --target x86_64-unknown-none --locked
cargo test --no-default-features --lib --test no_std --test no_std_readers --test no_std_owned --locked
cargo clippy --no-default-features --all-targets --locked -- -D warnings
```

The final application supplies an allocator, panic handling and its storage
backend. Targets must support pointer and 64-bit atomics. Implement
`partmgr::io::ReadAt` for immutable positional reads and `storage::Storage` for
exclusive writes and durable flushes. The portable I/O module retains typed
errors, reader provenance, bounded views and metadata budgets by reexporting
virtdisk 0.3.1's shared API in both configurations. Host image/file adapters
require `std`. Host backends convert standard I/O errors into the shared portable
error type; positional-reader identities and budgets use the same upstream types.

Portable caches use non-poisoning spin locks. Callers must prevent interrupt
handlers or backend callbacks from reentering the same cached reader while it
holds its lock. Portable hash maps use hashbrown's allocation-only default hasher;
no operating-system randomness is required. All existing format limits and
memory reservations remain active.

APFS and HFS+ owned metadata discovery runs synchronously without `std`. It
retains a single page index, retries the decoder when another page is required,
and charges every additional decoder pass against the explicit work ceiling.
This path can require a larger work budget than the default scoped-thread
implementation. Payload reads stay deferred. JFFS2 ZLIB decoding and encoding
use bounded miniz_oxide buffers in both builds.

The separate optical integration remains a host crate. The proposed upstream
portable virtdisk boundary is documented in
[the virtdisk refactoring plan](docs/virtdisk-no-std-plan.md).

The development filesystem framework provides lossless contracts, bounded
storage sessions and indexed positional reads. Explicit read-profile dispatch
covers conventional FAT, classic ext2, exFAT1.00, NTFS3.1 native indexes and an explicit XFS v5 baseline;
allocation evidence and namespace omissions remain visible. Deterministic FAT
classic ext2 and exFAT builders accept deferred trees, with explicit content-only copy
policies and staged verification. Classic ext2 capture preserves regular hardlink identities. Owned FAT and exFAT editors replace, extend and truncate files through external undo recovery; FAT and exFAT namespace operations have independent recovery gates. A declared logical NOR emulator enforces flash transitions and erase geometry. The separate optical integration uses published libmkiso0.1.4 and
virtdisk0.2.0. The new partmgr APIs and portable compatibility need further
release gates. See [filesystem support](docs/filesystem-support.md),
[read facade](docs/filesystem-image.md) and
[native validation](docs/filesystem-native-validation.md) for exact profiles,
evidence and remaining work. `FILESYSTEM_PLAN.md` remains ongoing.

The `std` [classic-ext3 ordered session](docs/filesystem-ext-journal-edit.md)
provides owned append/create/truncate, range overwrite, sparse extension,
hardlink and namespace editing with explicit recovery. Manifest seven integrates
unfollowed symlink creation, target replacement, reading, rename and unlink;
all five source-bound host checks pass
([365-source receipt](/data/cache/partmgr-maintenance-ext-symlink-checks-20261011-v5/result.json));
source-bound native interruption/recovery, adversarial controls and final rehash pass for the archived manifest-seven snapshot.
The [current implementation checkpoint](docs/filesystem-maintenance-status.md#current-implementation-checkpoint--2026-10-12)
also distinguishes unintegrated preallocation, counter-repair and NTFS drafts. Earlier manifest-six
sparse extension has scoped host/native and adversarial qualification bound to
its archived revision. Modern ext4 and NTFS transactional writers remain
unfinished; see the [maintenance inventory](docs/filesystem-maintenance-status.md).

```rust
use partmgr::{guid::Guid, layout::{Geometry, GptLayout}};

let geometry = Geometry::new(64 * 1024 * 1024, 512)?;
let disk_id: Guid = "00112233-4455-6677-8899-aabbccddeeff".parse()?;
let proposal = GptLayout::initialize(geometry, disk_id, 128, 128)?;
```

Use `error::inspect` for strict borrowed-reader inspection. GPT and basic MBR
models retain supported raw metadata. `editor::Editor` keeps original metadata
separate from a proposal and exposes boundary changes and filesystem prerequisites.
`codec::edit_plan` and `codec::initialize_plan` contain exact expected/replacement
bytes and ordered flush barriers. `codec::commit_and_inspect` rereads and validates
the committed table. `storage::FileStorage` exclusively locks regular image files;
on systems with advisory locks every writer must honor that lock. Custom storage
adapters must provide exclusive access and durable flushes.
See `examples/rename-gpt.rs` for inspection and a verified commit using a single
exclusively held image adapter.

GPT commits flush backup metadata before primary metadata. Initialization writes
the protective MBR last. Commits are not atomic: failures report completed stages
and uncertain durability. Inspect with `recovery::RecoveryReport` after interruption
and explicitly select a valid source, including when valid copies disagree.
`recovery::resize_gpt` coordinates metadata relocation and physical image resizing
through `ResizableStorage`; shrink commits metadata before truncating storage.

Extended MBR uses `extended::ExtendedLayout` with bounded EBR traversal. Conversion
requires explicit type mappings, disk identities, and a boot-code policy; metadata
must fit without moving payloads. Unknown extensions and dynamic-volume editing
are refused. Recognition of a partition type does not establish volume support.

`uefi` provides ESP policies, hard-drive device paths, and FAT/boot preparation
adapters. A valid layout does not prove bootability. The separate firmware gate
constructs representative images and requires observed EFI execution under OVMF.

`payload::CopyOperation` snapshots to an independent recovery medium before copying,
uses bounded RAM, verifies SHA-256 integrity, and resumes from durable journal
records. Recovery storage needs the full image length plus journal space. Keep it
until the associated layout commit completes. Filesystem growth follows partition
growth; filesystem shrink completes before partition shrink. A boundary-only edit
performs neither data movement nor filesystem resizing.

Required local checks:

```sh
cargo fmt -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

The test profile optimizes the exhaustive filesystem audit and recovery-cut loops.
Debug assertions and integer overflow checks remain enabled.

Host checks do not establish Windows servicing or capture correctness. See
`scripts/firmware-gate.py` for the separate firmware run and its explicit tool
dependencies. Tests requiring external tools must be run explicitly; a skipped
test is not verification evidence.
