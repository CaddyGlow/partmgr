# PLAN.md implementation verification

The implemented scope is partition metadata management plus explicit filesystem,
boot-preparation, and payload-operation adapters. Formatting filesystems, installing
production bootloaders, firmware variable management, Secure Boot, hybrid MBR, and
dynamic-volume management remain separate components as specified by PLAN.md.

## Milestone evidence

| Milestone | Implementation and concrete verification |
| --- | --- |
| 1: Lossless inspection | `layout.rs` separates owned GPT/basic MBR models, strict inspection, raw inspection, and borrowed bounded partition views. `tests/layout.rs` independently constructs 512/4096 GPT and MBR metadata, preserves disk identity/slots/CHS/boot bytes/UTF-16/opaque unused fields, rejects CRC/copy/ID/overlap/bounds errors, and checks sparse geometry/resource limits. Unknown headers, reserved attributes, and nonzero extended entry tails remain available through raw inspection but cannot be mutated. LDM recognition does not authorize standalone-volume interpretation or dynamic-volume mutation. Existing malformed-image regressions remain in `tests/partitions.rs`. |
| 2: GUIDs, names, attributes | `guid.rs` supplies canonical GUID traits and mixed-endian GPT conversion, known type lookup, checked UTF-16 names and type-specific bit helpers. `tests/guid.rs` uses independent GUID vectors, tests malformed/nil/duplicate IDs, supplied IDs, collision retries and entropy errors, surrogate pairs/36-unit limits/raw invalid UTF-16, embedded-NUL rejection, and preservation of unrelated attributes. |
| 3: Pure editing | Owned layout methods initialize/create/delete/rename/change identity/type/attributes/boundaries transactionally. GPT, MBR, and EBR placement accepts explicit alignment and checked geometry. `tests/layout.rs` checks exact fits, gaps, failed-edit preservation, slot/range limits, and exhaustive alignment properties. `editor.rs` retains original inspection independently of proposal and committed baseline, reports old/new ranges and prerequisites, and exposes explicit boundary-only commits. `tests/editor.rs` verifies filesystem ordering, failure preservation, successive baselines, verified adoption, and blocking reuse after partial commits. |
| 4: Serialization and commits | Published `virtdisk` 0.1.0 was inspected and provides read access only. `storage.rs` defines positional writes, exact short-write completion, durable flushes, geometry/source preconditions, reviewable ranges/barriers, source-preserving errors, and a locked regular-file adapter. `codec.rs` orders backup GPT before primary and initialization PMBR last, preserves 4096-sector MBR tails, and strictly reinspects committed storage. `tests/storage.rs`, `tests/codec.rs`, and `tests/initialization.rs` exercise every write/flush boundary, stale metadata/geometry, short writes, preflight I/O, uncertain durability, exact preservation, independent CRCs, and explicit recovery outcomes. `tests/conversion_failures.rs` covers conversion publication and cleanup failures. Atomic file replacement was considered; this adapter deliberately provides tested in-place commits and makes no atomic replacement or block-device atomicity claim. |
| 5: Recovery and geometry | `recovery.rs` reports primary/backup/candidate results independently, requires explicit selection, bounds displaced discovery to 64 caller-selected LBAs, snapshots selected metadata, and refuses stale or unknown/hybrid sources. `tests/recovery.rs` covers either/both damaged copies, valid divergence, displaced former-final backups, noncanonical array placement, custom usable bounds, damaged PMBR, stale sources, growth relocation, and shrink rejection. `resize_gpt` coordinates `ResizableStorage`: grow storage before relocation, commit shrink metadata before physical truncation, then strictly reread. |
| 6: Extended MBR and conversion | `extended.rs` models containers, primaries, logical partitions and exact EBR sectors; validates both relative addressing bases, link lengths, cycles, chain limits, bounds, and metadata/payload overlap. Edits cover insertion, first/final deletion, empty chains and explicit EBR placement. `tests/extended.rs` includes independent 512/4096 fixtures and all 1,539 one-byte-write/flush interruption boundaries with explicit retained-snapshot rollback. `conversion.rs` requires explicit type maps/identities/boot-code policy, rejects unsupported limits/unknown mappings/dynamic layouts, preserves payload positions, and clears obsolete metadata safely. `tests/conversion.rs`, `tests/conversion_failures.rs`, and `tests/independent.rs` verify independent payload SHA-256 before/after and at every conversion failure boundary, including overlapping obsolete EBR/GPT metadata. |
| 7: UEFI and ESP | `uefi.rs` creates/recognizes ESP metadata, validates configurable Windows/Linux policies, encodes independently verified hard-drive device paths, and separates FAT/boot preparation outcomes. Logical MBR ESP recognition does not promise firmware discovery; UEFI MBR hard-drive device-path partition numbers remain 1–4. `tests/uefi.rs` covers independent byte vectors, profile validation, and preparation failures. `examples/firmware-image.rs` plus `scripts/firmware-gate.py` generate representative GPT/MBR images, independently prepare FAT/install an EFI test executable, and require its observed marker under QEMU/OVMF. Firmware variable and Secure Boot permissions remain outside the core. |
| 8: Payload and resizing | `payload.rs` uses an independent full-image recovery snapshot with bounded RAM, SHA-256 integrity checks, alternating journal records and pending-chunk recovery. `tests/payload.rs` exercises disjoint/overlapping copies, both directions, progress/cancellation, changed storage, torn writes/journals, disk/journal flush failures, interrupted/resumed copying, and filesystem ordering. An interrupted pending chunk finishes before cancellation can return a clean durable boundary. Layout commits require verified payload completion; an end-to-end test copies payload then commits/reinspects its GPT range change. |

All public APIs are documented and compiled with missing-documentation denial.
Domain errors separate invalid data, unsupported semantics, invalid edits, stale
plans, ordinary I/O, and partial commits while preserving error sources. The
low-level codec/model methods also expose familiar `io::Result` interfaces.

## Final gate evidence

Final verification on 2026-10-07:

- Required formatting, Clippy with `-D warnings`, and locked all-feature tests pass.
- Linux and Windows portable tests each pass 89 tests. Windows binaries were
  cross-compiled for MSVC with static CRT and actually executed in an isolated
  Windows 11 guest (NT 10.0.26200.0). The isolated VM was shut down afterward.
- All five explicitly external-tool tests pass separately on Linux with available
  `sfdisk`/`sgdisk`, including emitted basic/extended conversions at both logical
  sector sizes and an 8 TiB sparse image. They remain explicitly ignored in the
  portable suite rather than falsely counted as portable verification.
- Fuzz formatting, Clippy, and harness tests pass. Four instrumented targets each
  finish 1,000 requested iterations with zero crashes/timeouts; the layout target
  includes codecs, edit sequences, EBR traversal, recovery selection and write
  plans. This is a bounded campaign, not a security qualification.
- GPT and MBR representative 512-byte-sector images each exit QEMU with code 33
  after the independently built EFI executable emits `PARTMGR_FIRMWARE_OK`.
- Documentation builds pass with rustdoc warnings denied. README, repository
  guidelines, crate docs, examples, fuzz documentation, and CI are updated.

The local receipts and complete logs are retained at:

| Gate | Receipt |
| --- | --- |
| Required checks, external tools, fuzz harness, documentation | `/data/cache/partmgr-final-verification-20261007/receipt.json` |
| Actual Windows execution, binary/source hashes | `/data/cache/partmgr-windows-20261007/receipt.json` |
| Instrumented fuzz campaigns | `/data/cache/partmgr-fuzz-20261007-verified/summary.json` |
| Observed OVMF boot | `/data/cache/partmgr-firmware-20261007-final/receipt.json` |

`.github/workflows/ci.yml` retains native Linux/Windows portable jobs and adds an
explicit independent-tool job. `.github/workflows/firmware.yml` is a separate
firmware integration job. Hosted Actions were not dispatched from this uncommitted
worktree; the above portable/runtime/tool/firmware gates were executed locally.

## Operational limits

GPT redundancy does not make commits atomic. EBR has no redundant copy: rollback
requires an explicitly retained trusted metadata snapshot outside overwritten
sectors. Conversion can make an old EBR chain unreadable before scheme publication
when new GPT metadata overlaps it; failure tests document this outcome. All
adapters and callers must enforce exclusive access for inspection/preflight/write/
flush/readback. Unix file locks can be advisory, so every writer must honor them.

Payload recovery consumes an independent disk-sized snapshot plus journal space;
it is not merely a copy cursor and does not promise recovery without that snapshot.
Retain recovery storage until the associated metadata commit completes. Boundary-
only edits do not move data or resize filesystems. Adapter success must mean its
documented durability/verification contract completed.

Observed firmware evidence covers the representative x86-64 fallback EFI images
only. It does not establish production bootloader compatibility, Secure Boot,
Windows servicing, or capture correctness. The unrelated `FILESYSTEM_PLAN.md`
was not part of this implementation.

Normative requirements were checked against the official UEFI GPT disk-format,
media-access, and device-path specifications linked from PLAN.md and the API docs.
