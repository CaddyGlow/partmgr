# Partition manipulation and GUID/UEFI implementation plan

## Objective

Evolve `partmgr` into an idiomatic Rust library for inspecting, creating, editing,
validating, serializing, committing, and recovering GPT and MBR partition tables.
Include typed GUIDs, EFI System Partition support, extended MBR, scheme conversion,
and a later layer for partition payload operations.

Backward compatibility is not required. Replace the current API where doing so
improves correctness, ownership, clarity, or representation of on-disk formats.
Retain strict read-only inspection as a capability, without preserving its current
types or signatures.

UEFI support means standards-compliant disk layouts and explicit integration with
ESP preparation and boot tooling. Firmware services, Secure Boot, filesystem
formatting, bootloader installation, and dynamic-volume management are separate
components with explicit boundaries. A valid GPT or ESP type does not establish
that a disk boots.

## Development method

Implement each milestone test first:

1. Specify observable behavior and failure cases with fixtures or independent
   reference vectors.
2. Add focused failing tests and confirm that they fail for the intended reason.
3. Implement the smallest complete behavior that passes those tests.
4. Refactor into idiomatic Rust while keeping tests passing.
5. Run the required repository checks before completing the milestone.

Use meaningful behavioral tests rather than tests that duplicate implementation
logic. Keep fixture generation independent of the production codec where possible.
Test failures and preservation guarantees alongside successful operations. Carry
forward existing malformed-image regressions while replacing obsolete API tests.

Required checks:

```sh
cargo fmt -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

Published dependencies must resolve from crates.io. Host tests do not establish
Windows servicing, capture correctness, or firmware boot correctness.

## API and architecture

- Separate byte decoding/encoding, validated layout models, edit planning, and
  storage commits. Keep platform-specific boot and filesystem operations outside
  the core table model.
- Use format-specific enums and structs, such as `DiskLayout::Gpt(GptLayout)` and
  `DiskLayout::Mbr(MbrLayout)`, instead of combinations of optional GPT/MBR fields.
- Use private fields, checked constructors, and explicit methods to protect
  invariants. Avoid unnecessary typestate, generic parameters, or abstractions.
- Represent GUIDs, logical geometry, partition identity, and ranges with small
  types where they prevent actual mistakes. Define inclusive on-disk versus
  exclusive internal range conversions explicitly and use checked arithmetic.
- Return documented domain errors implementing `Display` and `Error`; retain
  underlying I/O errors as sources. Distinguish invalid data, unsupported features,
  invalid edits, stale plans, and partially completed commits.
- Keep immutable inspected state separate from a proposed editable layout.
  Validate proposed layouts before producing write plans.
- Prefer borrowed accessors and iterators, owned editable layouts, and explicit
  storage capabilities. Do not bind the layout model to an `Arc`-owned reader.
- Document all public APIs and keep dependencies and feature flags justified by
  concrete requirements.

Names in this plan are illustrative; finalize them through implementation and
small usage examples, not compatibility with existing names.

## Milestone 1: Lossless format model and strict inspection

Tests first:

- Decode independently produced GPT and basic MBR fixtures at 512-byte and
  4096-byte logical sector sizes.
- Preserve GPT disk identity, usable bounds, entry dimensions and slots; preserve
  MBR disk signature, boot flags, CHS fields, and boot-code bytes.
- Cover malformed headers, CRC failures, inconsistent copies, duplicate IDs,
  overlaps, bounds, allocation limits, and unsupported extensions.
- Verify exact preservation of supported raw metadata, including UTF-16 name
  fields, unused entries, and bytes beyond the known entry prefix.

Implementation:

- Introduce owned GPT/MBR models and separate raw inspection from validated layout
  access. Keep bounded read-only partition views available through explicit APIs.
- Preserve supported opaque bytes during edits; refuse mutation of extensions
  whose semantics or preservation requirements cannot be established.
- Separate partition-table validity from whether a partition can be interpreted
  as a standalone volume. Do not mistake recognition of an LDM type for LDM support.
- Audit validation against UEFI GPT requirements, with documented resource limits.

Acceptance: supported metadata is retained without unintended changes, and strict
inspection remains bounded and rejects invalid layouts.

## Milestone 2: GUIDs, names, and attributes

Tests first:

- Check canonical GUID parsing/display and mixed-endian GPT encoding against
  independent known vectors; reject malformed text.
- Check nil IDs, duplicate IDs, supplied IDs, and generated-ID collision handling.
- Check 36-unit GPT name limits, surrogate pairs, invalid UTF-16 preservation, and
  explicit raw versus string name access.
- Check attribute mutation preserves unrelated bits and accounts for type-specific
  attribute meanings.

Implementation:

- Add a `Guid` value type with appropriate standard traits and explicit on-disk
  conversions. Choose an established crates.io implementation if it fits these
  requirements without obscuring the encoding boundary.
- Provide common partition-type constants and descriptive lookup while accepting
  unknown type GUIDs.
- Add checked name setters and attribute helpers; generation must have a fallible
  entropy path or accept caller-provided IDs.

Acceptance: identifiers have unambiguous representations and setters cannot
silently truncate names or discard unrelated attribute bits.

## Milestone 3: Pure layout editing

Tests first:

- Exercise initialization, create/delete, rename, type/ID/attribute changes, and
  partition boundary changes without storage writes.
- Check free-space enumeration, exact fits, alignment, fragmented gaps, slot
  exhaustion, metadata exclusion, overflow, and scheme-specific limits.
- Verify failed edits leave the proposed layout unchanged.
- Distinguish partition boundary changes from filesystem resizing or data movement.

Implementation:

- Add an editor over owned layouts, checked placement policies, and explicit
  geometry/alignment inputs.
- Produce a reviewable change description with old/new ranges and any required
  payload or filesystem prerequisites.
- Require completed filesystem shrink work before a managed shrink operation
  commits a smaller containing partition; expose boundary-only edits explicitly.

Acceptance: every edit yields a validated proposal or a precise error, with no I/O
side effects.

## Milestone 4: Serialization and durable storage commits

Tests first:

- Round-trip supported layouts and independently verify emitted CRCs and positions.
- Assert exact write ranges and preservation of unaffected bytes, including the
  remainder of a 4096-byte sector containing the MBR.
- Inject short writes, I/O failures, flush failures, and interruption after each
  write/flush boundary.
- Reject stale plans when expected metadata or disk geometry has changed.
- Verify successful commits by re-reading storage, not just the proposed model.

Implementation:

- Inspect the published `virtdisk` capabilities before choosing a writable adapter.
  Define explicit random-access writes, exact-write handling, and durable flush
  requirements where the dependency does not provide them.
- Produce deterministic write plans containing preconditions, affected ranges,
  replacement bytes, and ordered durability barriers.
- Require exclusive access through an enforceable adapter or an explicit caller
  contract; precondition checks alone do not prevent concurrent writers.
- For existing GPT edits, write and flush the backup array/header before updating
  and flushing the primary copy. Specify separate ordering and recovery outcomes
  for initialization, conversion, and protective-MBR updates.
- Report completed stages and uncertain durability on failure. GPT redundancy does
  not make in-place commits atomic. Consider atomic file replacement for suitable
  image-file adapters without promising it for block devices.

Acceptance: every failure boundary has a tested, documented inspection/recovery
outcome, and successful commits pass independent revalidation.

## Milestone 5: GPT recovery and disk geometry changes

Tests first:

- Inspect either damaged copy, both damaged copies, and valid but divergent copies.
- Repair from an explicitly selected valid source; never silently choose between
  conflicting valid layouts.
- Cover grown images whose old backup header remains at the former final LBA.
- Reject shrink operations that intersect partitions or required GPT metadata.

Implementation:

- Add recovery reports separate from strict inspection and explicit repair plans.
- Support backup relocation and usable-range updates after growth.
- Define bounded discovery rules for displaced metadata and distinguish repairable
  geometry from ambiguous or untrusted candidates.
- Plan shrink metadata against the intended final geometry, coordinating actual
  storage resizing through the adapter rather than assuming it is already safe.

Acceptance: repair choices are explicit, validated, and use the tested commit
pipeline.

## Milestone 6: Extended MBR and scheme conversion

Tests first:

- Cover EBR chains, both relative-LBA bases, cycles, malformed links, bounds,
  overlaps, chain limits, and logical-partition edits.
- Cross-check GPT/MBR conversions with explicit type mappings and unchanged payload
  hashes.
- Reject conversion when MBR address limits, partition counts, GPT metadata space,
  or unknown type mappings prevent a valid result.

Implementation:

- Add extended-container and logical-partition models, bounded EBR traversal, and
  EBR serialization with explicit commit/failure ordering.
- Implement GPT-to-MBR and MBR-to-GPT plans, including logical partitions, disk
  identity changes, obsolete-metadata handling, and boot-code policy.
- Preserve payload positions by default; require a separate movement operation
  when metadata cannot fit.
- Keep hybrid MBR and dynamic-volume editing out of ordinary conversion paths.
  Supporting them requires separate designs and tests.

Acceptance: independently readable converted layouts preserve payload bytes and
make identity and boot implications visible.

## Milestone 7: UEFI and ESP integration

Tests first:

- Recognize and create ESP entries on GPT and supported MBR layouts.
- Validate configurable Windows/Linux layout profiles without claiming that one
  universal ESP size or layout suits every platform.
- Verify UEFI hard-drive device-path fields with independent byte vectors.
- Exercise filesystem/boot integration through test adapters, then boot generated
  representative images under QEMU/OVMF.

Implementation:

- Provide ESP and platform layout helpers with explicit policy inputs.
- Define adapters for FAT preparation, boot-file installation, and device-path
  generation.
- Keep firmware `Boot####`/`BootOrder` management and Secure Boot integration in a
  platform layer with independent permissions and validation.
- Report layout validity, ESP preparation, and observed firmware boot as separate
  outcomes.

Acceptance: layout helpers pass core tests and actual boot claims are supported by
firmware integration runs.

## Milestone 8: Payload copy, move, and filesystem resizing

Tests first:

- Cover disjoint and overlapping copies in both directions, bounded memory use,
  cancellation, progress, I/O failure, and interrupted/resumed operations.
- Verify payload hashes and operation-record integrity; reject resumption against
  changed storage.
- Test filesystem resize ordering and adapter failures separately from table edits.

Implementation:

- Add a distinct payload-operation layer with overlap-safe copying and persisted
  recovery records appropriate to each operation.
- Design recoverability before exposing destructive in-place movement; a copy
  cursor alone is insufficient when overwritten source data is needed on resume.
- Integrate filesystem-aware resizing through dedicated adapters. Grow the
  containing partition before filesystem growth; shrink the filesystem before
  partition shrink.
- Commit layout changes only when the corresponding payload prerequisites hold.

Acceptance: supported operations preserve payloads, honor cancellation semantics,
and have demonstrated failure recovery.

## Cross-cutting verification and release gates

- Extend the existing fuzz harness to codecs, GUID parsing, edit sequences, EBR
  traversal, recovery selection, and write-plan validation.
- Use property tests for preservation, invariant maintenance, and checked range
  conversions, supplemented by independent fixtures and external-tool checks.
- Verify generated images with independent tools such as `sfdisk`/`sgdisk`; make
  tool availability explicit rather than silently treating skipped checks as proof.
- Exercise sparse large images, 512/4096-byte logical sectors, configurable physical
  alignment, and resource limits without allocating disk-sized buffers.
- Run Linux and Windows CI for portable library behavior, with separate firmware
  and platform integration jobs for stronger claims.
- Update README, crate documentation, examples, and repository guidelines as the
  read-only scope changes. Correct the stale sibling-checkout instruction in README.

## Delivery sequence

First deliver milestones 1–5: typed GUIDs, a validated format model, pure editing,
GPT/basic-MBR writing, and explicit GPT recovery. Then deliver extended MBR and
conversion, UEFI integration, and finally payload operations. Each milestone must
include its tests, public documentation, examples where useful, and completed
required checks before proceeding.

## Standards references

- [UEFI 2.11 GPT disk layout](https://uefi.org/specs/UEFI/2.11/05_GUID_Partition_Table_Format.html)
- [UEFI media-access protocols and ESP discovery](https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html)

Recheck applicable normative requirements during implementation; partition layout,
filesystem compatibility, and firmware behavior require different evidence.
