# NTFS and FAT forensic tools implementation plan

Status: implementation in progress; see [current evidence and remaining work](filesystem-forensics-status.md).
Scope: read-only NTFS and FAT12/16/32 (including VFAT) inspection, extraction,
deleted-entry analysis and timelines. exFAT requires its own later profile.
This refines the forensic workstream in `FILESYSTEM_PLAN.md`.

## Existing foundation and gaps

- Both filesystem readers already consume `Arc<dyn virtdisk::ReadAt>`.
  `virtdisk::DiskView` provides a bounded volume region; container decoding stays
  in virtdisk. Development temporarily uses the user-authorized `../virtdisk`
  path dependency; return to a published crates.io release before release validation.
- Raw/dd regular files can use `RawDisk`; supported containers can use `Image`
  with explicit format, parent authorization and recovery policies.
- The sibling virtdisk now provides `PhysicalDisk`, a read-only `ReadAt` adapter
  under `std` on Linux and Windows. It queries capacity and logical sector size
  and handles unaligned byte reads through bounded sector reads. Linux supports
  block devices including partitions; Windows accepts `\\.\PhysicalDriveN` paths
  only, not volume or snapshot paths. `RawDisk` remains for regular files.
  Partmgr temporarily resolves the sibling checkout to use this adapter. The
  registry `virtdisk 0.3.0` lacks it, so published builds require a newer release
  containing the API and validation against that release.
- FAT exposes geometry, allocation entries, strict live namespace reads and
  file extents. Live directory enumeration excludes deleted slots.
- NTFS exposes strict allocated-record reads, stream/native metadata profiles,
  security, compression and bounded selected USN stream extraction. Strict
  volume opening rejects dirty flags. Existing log parsing is not a general
  forensic acquisition, recovery or replay guarantee.

## Architecture and evidence contract

All new forensic APIs are opt-in behind a Cargo `forensics` feature, excluded
from default features. Define `forensics = []` when the first implementation
lands; it must not imply `std`. Gate public modules, forensic-only implementations
and their tests with `#[cfg(feature = "forensics")]`. Shared decoding and existing
filesystem/USN/log APIs retain their current availability.

Portable forensic decoding supports `--no-default-features --features forensics`.
Host source adapters and filesystem exports additionally require `std`; gate
those APIs on both features. An in-package forensic binary or example declares
`required-features = ["std", "forensics"]`. Any added forensic dependencies must
be optional and activated by the appropriate feature. A separate CLI package
must explicitly enable `partmgr`'s `std` and `forensics` features.

One portable forensic layer accepts a stable bounded `ReadAt` source. Host
opening and CLI/export code require `std`; decoding should retain the crate's
portable allocation and resource conventions. Keep strict reader behavior intact;
share checked low-level decoding where appropriate, with explicit forensic entry
points and typed observations rather than a global permissive-reader switch.

Each observation identifies its source, volume byte range, logical stream/record
offset, raw evidence and validation outcome. Distinguish validated structures,
partial evidence, rejected candidates and inferred associations. A validated
structure does not establish historical authenticity or original recovered data.
Keep container-file offsets distinct from virtual-disk offsets: `ReadAt` alone
does not promise a physical container mapping.

Preserve native name units, unknown fields, timestamp representation and
precision. Bind extracted output to source ranges, hashes, holes, unreadable
ranges, allocation/reuse conflicts and completeness. A caller label is not a
verified digest. Record acquisition identity and stability method separately;
hash manifests explicitly distinguish original container bytes, logical disk
bytes, selected evidence ranges and extracted outputs.

Use bounded visitors, shared memory reservations, cancellation and independent
scan/record/read/output limits. I/O failures retain their causes. Never turn an
unreadable range into zero or concatenate data across a missing range. Tolerant
scans may continue only at explicit independent boundaries and must emit gaps.

Every library scan returns a typed completion outcome, including scans stopped
before their first observation. Identify the requested domain and profile,
inspected coverage, skipped/unreadable/unsupported ranges, unvisited remainder,
and stop reason. Distinguish completed traversal from cancellation, caller stop,
resource exhaustion, I/O failure, invalid bootstrap, unsupported profile and
source-stability failure. Preserve the causal error and previously delivered
observations when stopping. Traversal completion and evidence validity are
separate: visiting every slot does not mean every slot decoded successfully.

Stream bounded coverage events alongside findings; the final outcome carries
bounded counters and coverage status rather than retaining an unbounded list of
ranges. Counts alone must never imply full coverage. If a visitor/output failure
prevents delivery, return an incomplete outcome identifying the last delivered
position and failed delivery; an export without a terminal outcome is incomplete.
An empty completed scan must be distinguishable from a scan that never started.

## Delivery sequence

### 1. Source adapters and evidence plumbing

Implement source selection for explicit raw files, supported virtdisk containers,
whole disks, partition selections and explicit offset/length regions. Require
explicit sector geometry where partition interpretation cannot establish it.
Retain source identity and region translation through observations and exports.
Implement the shared scan outcome and coverage-event contract in this step,
before filesystem-specific visitors or CLI export. Reserve resources needed to
report termination before scanning so budget exhaustion can still return status.

Integrate virtdisk's existing `PhysicalDisk::open` and `logical_sector_size` using
the temporary `../virtdisk` path dependency. Before release, remove the path,
select a published version containing these APIs, update the lockfile and rerun
qualification against that version. Gate the partmgr host
integration on `std`, `forensics` and Linux/Windows. Use `DiskView` for selected
disk regions and keep sector geometry available to partition selection.

Capacity queries, bounds checks and sector-aligned backing reads belong to
virtdisk. The adapter supplies no snapshot, external-writer lock or host-file
source identity, and captures geometry at open rather than monitoring media
changes. Partmgr must supply the acquisition identity/stability contract below
and preserve causal read/removal errors. Windows volume/VSS handle access remains
a separate adapter dependency if that source profile is added. Native-device
support ships per tested OS.

Require a stable acquisition, snapshot or offline device held stable for the
entire forensic session, including deferred reads. Record the stability provider,
identity and lifetime; reject direct live-device analysis when this prerequisite
cannot be met. Opening a device read-only or checking its size does not establish
stability. On detected stability loss, stop with incomplete coverage and invalidate
deferred handles; generic same-length byte changes cannot always be detected.

Live acquisition is a separate future host workflow: it must first produce a
closed, stable artifact and acquisition manifest before forensic `ReadAt` readers
open it. Record acquisition times, unreadable ranges and consistency uncertainty;
a stable artifact captured from changing media is not necessarily a consistent
point-in-time filesystem. Missing acquired ranges remain unavailable through an
explicit range map, even if the artifact file stores zero-filled placeholders.
Container parent chains and any immutable recovery overlay are explicit evidence
inputs recorded in the manifest.

Gate: identical logical observations for the same bytes as a dd file, a container
and a bounded device view; wrong lengths, boundaries, sector alignment, I/O faults
and cancellation covered. Use disposable loop devices and Windows test disks for
native adapter gates; ordinary in-memory tests do not establish device behavior.
Reuse upstream `scripts/test-physical-disk.sh`, `scripts/test-physical-disk.ps1`
and `tests/physical_disk.rs` for adapter qualification; retain native run evidence
for the consumed release. Their existence or CI configuration alone is not a
passing receipt. Add partmgr filesystem/partition equivalence tests on top of
those adapter tests, including Linux 512-byte and 4096-byte logical sectors.
Test rejected unstable sources and detected stability loss during deferred reads.
Test empty success, failure before the first observation, mid-scan cancellation,
each resource ceiling, visitor failure and unreadable ranges; assert exact coverage
and stop reasons with prior observations retained. Compare backend-independent
facts while preserving distinct source identities and acquisition manifests.

### 2. NTFS forensic MFT inventory

Add bounded observation of allocated and unallocated MFT slots, raw and
fixup-validated records, sequence numbers, base/extension references, native
attributes, both timestamp sets and names. Dirty volumes must be inspectable
without replay, repair or clean-marker changes. Report bootstrap failure,
unsupported mapping, truncation, bad fixups and mirror disagreement explicitly.
Any raw signature scan is a separate candidate profile, not MFT enumeration.

Read `$MFT::$BITMAP` and retain each available allocation bit independently of
the FILE in-use flag. Report disagreements and unavailable bitmap ranges rather
than classifying records from one field alone. An unallocated slot may be unused,
deleted or stale; retain that distinction and the supporting record evidence.
Read the volume `$Bitmap` for current cluster allocation and build bounded current
stream-ownership observations from allocated records, including supported ADS
and attribute-list extensions. Reuse the existing audit decoders where possible,
but preserve partial evidence when a full strict audit cannot complete.

Allocation bits, current owners and historical reuse are separate observations.
Record coverage of both bitmaps and the ownership scan; when a bitmap is missing,
a mapping is unsupported or an owner scan is incomplete, mark the corresponding
allocation/ownership conclusion unknown. Absence of an observed owner establishes
no conflict-free claim unless the relevant ownership domain was fully inspected.

Gate: independent clean/dirty/deleted/reused-record fixtures, damaged fixups,
fragmented MFT and extension records, truncation and mirror conflicts. Preserve
bad raw records without interpreting invalid attributes as validated evidence.
Include bitmap/FILE-flag disagreement, missing/truncated bitmaps, allocated
clusters without resolved owners, conflicting current stream ownership and
interrupted ownership scans. Assert that unavailable evidence remains unknown.

### 3. FAT forensic slot and allocation inventory

Visit raw directory slots with exact offsets, including deleted entries, LFN
fragments, labels, terminators and separately identified post-terminator slack.
Retain raw timestamps and BPB context. Deleted aliases have a lost first byte;
deleted LFN reconstruction must remain an inference with its supporting slots.
Inspect each FAT copy, free/bad/reserved entries, divergent chains, cycles,
cross-links and orphan allocation under explicit scan limits.

Gate: FAT12 packed entries, FAT16 fixed roots and FAT32 root chains; native
deletions, cleared chains, overwritten slots, conflicting FATs, broken LFNs,
timestamp edge cases and post-terminator negative controls.

### 4. Extraction and metadata-assisted recovery

Extract supported live NTFS streams/ADS and FAT files with streaming hashes and
manifests. Represent sparse, unwritten and unavailable ranges distinctly. Add
deleted-record/slot recovery only with explicit range and reuse observations.
For NTFS, compare each candidate physical extent against the step 2 volume bitmap
and current stream-ownership evidence. Retain current allocation, known conflicting
owners and unknown coverage per range in the extraction manifest. Do not label
unavailable or incomplete checks as clear; distinguish observed current conflicts
from inferred historical reuse. Recovery may export candidate bytes with these
qualifications, but cannot promote them to verified historical content.
Current free allocation does not prove that clusters retain original contents.
FAT contiguous reconstruction is an opt-in hypothesis when the chain is lost.
Keep signature carving a later independent capability.

Create output files exclusively, sanitize display paths, preserve native names
in manifests, handle collisions deterministically and never follow evidence
paths outside the output directory. Keep incomplete output visibly partial.

Gate: exact known-content hashes, fragmented and resident data, ADS, supported
compression/sparse profiles, reused clusters, missing ranges, hostile names,
output failures and cancellation. Recovered historical content must not acquire
a verified-original claim merely because extraction completed.
Cover missing allocation evidence and partially scanned current owners as well
as known reuse; manifests must preserve unknown/conflicting ranges and the shared
scan outcome independently of the output-byte hash.

### 5. Journals and timelines

Extend selected USN extraction with validated namespace discovery, `$Max`,
rollover and gap observations. Expose supported `$LogFile` observations separately
from USN and from replay. Stream MFT/FAT timestamp and journal events with exact
provenance; retain ambiguous paths, stale references and unmatched rename events.
FAT wall-clock timestamps need explicit timezone assumptions. Provide bounded
external sorting for chronological export.

Gate: Windows-created known-operation journals, rollover/truncation, reused IDs,
ambiguous links, timestamps with different precision and deterministic export.

### 6. User-facing tool and release gate

Expose inspection, inventory, extraction, recovery candidates and timeline
commands through a small CLI using the same public library APIs. Prefer a
separate binary package if CLI dependencies would expand the core library.
Provide versioned streaming JSON Lines observations and extraction manifests,
plus a human-readable summary. Report supported profiles and partial completion;
do not silently downgrade unsupported evidence or treat partial results as a
successful complete scan.
Serialize the library's coverage events and terminal outcome directly, including
causal stop reasons. A missing terminal record or failed output leaves the export
incomplete; the CLI must return a failure status for interrupted/incomplete work.

Compare inventories and extracted bytes against independent Sleuth Kit tools and
native Windows evidence for selected profiles. Retain fixture/tool versions,
commands, hashes and separate results for each backend and OS. Verify immutable
fixture hashes before and after inspection. Include malformed-input fuzzing,
resource exhaustion, unreadable ranges and interruption tests.

Required repository checks: `cargo fmt -- --check`,
`cargo clippy --all-targets --all-features --locked -- -D warnings`, and
`cargo test --all-features --locked`. Host tests do not prove native Windows
behavior, capture correctness or firmware boot correctness; the QEMU/OVMF
firmware gate remains separate.

Also check the feature matrix: default builds, `--no-default-features`,
`--no-default-features --features forensics`, and `--features forensics`.
Verify that default builds exclude the new forensic public API and forensic-only
dependencies, and that forensic tests run when the feature is enabled.

## First implementation milestone

Deliver step 1 stable-source/evidence/region plumbing, shared scan outcomes and
raw/container equivalence tests, then step 2 bounded MFT, bitmap and ownership
inventory and step 3 raw FAT slot inventory. Integrate the existing native device
adapter from the sibling checkout in step 1 with independent platform gates;
track upstream publication as a release dependency. This milestone must produce
inspectable observations before deleted-file
recovery or timeline inference is advertised. No journal editing, replay,
filesystem repair or source writes are authorized by this read-only plan.
