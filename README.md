# partmgr

Lossless GPT and MBR inspection, owned layout editing, deterministic write plans,
and explicit recovery. Partition metadata, filesystem operations, payload copying,
and observed firmware boot have separate APIs and outcomes.

```toml
partmgr = "0.1.0"
```

```sh
cargo test --all-features --locked
```

Dependencies resolve from crates.io; no sibling checkout is required. CI checks
formatting, Clippy and tests on Linux and Windows. Independent partition-tool and
QEMU/OVMF jobs provide additional format and firmware evidence.

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
