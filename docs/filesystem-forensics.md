# Read-only forensic tools

Enable the opt-in portable library with `--features forensics`. Host opening,
JSONL and exclusive file export also require `std`. Default builds exclude these
APIs. The CLI example requires both features:

```sh
cargo run --locked --features forensics --example filesystem-forensics -- --help
```

Every source must already be a stable acquisition, snapshot or offline artifact,
held stable externally for the entire process, including deferred reads. Opening
read-only, checking a file length and supplying a provider label do not establish
stability. The CLI requires an explicit assertion of that prerequisite and does
not open physical devices. Live acquisition, Windows volume/VSS access and
filesystem repair are separate workflows.

For a closed raw acquisition:

```sh
cargo run --locked --features forensics --example filesystem-forensics -- \
  inventory-ntfs disk.dd --format raw --sector-size 512 \
  --assert-stable --acquisition-id case-001 --stability-provider offline-artifact \
  --partition 1 > inventory.jsonl
```

Select a complete disk, a validated GPT/MBR partition with `--partition`, or an
explicit sector-aligned `--offset BYTES --length BYTES` region. The latter two
choices are mutually exclusive. Artifact geometry is always explicit. Containers
require `--format vdi|vhdx|qcow2|vmdk`; each parent must be independently authorized
with a repeated `--parent PATH`. Opening rejects pending recovery by default;
this tool never replays or writes source journals.

FAT profiles retain every directory slot, including deleted aliases, LFN fragments
and separately marked post-terminator slack. A supplied directory region is an
explicit caller selection; the raw slot profile does not prove namespace reachability:

```sh
cargo run --locked --features forensics --example filesystem-forensics -- \
  slots-fat floppy.dd --format raw --sector-size 512 \
  --assert-stable --acquisition-id case-002 --stability-provider offline-artifact \
  --directory-offset 9728 --directory-length 7168 > slots.jsonl
```

`allocation-fat` inspects all FAT copies. Its scan domain and coverage use
copy-major entry ordinals; observations separately retain exact volume and logical
disk byte ranges. NTFS inventory distinguishes raw slots, validated framing,
independent MFT bitmap bits, unavailable bitmap/mirror evidence and rejected
records. Raw attributes preserve names, timestamps and unknown native fields.
A validated record never authenticates historical content.

`compare-fat-copies` compares decoded values and exact packed backing bytes
against copy zero. `compare-fat-chains --start-cluster N --chain-transitions N`
follows each copy independently and retains divergent transitions and cycles,
including inactive FAT32 copies. Copy zero is a comparison baseline, not a
historical authority; raw FAT12 bytes may differ because adjacent entries share
packed storage. Limits and coverage retain independent incomplete outcomes.

`extract-ntfs --record N --output-dir DIRECTORY` exports a validated live DATA
stream. The unnamed stream is the default; `--stream-name-utf16 0041,0044,0053`
selects the exact native ADS units. `--allow-lznt1` explicitly enables the supported
compression profile. Resident, mapped, sparse and unwritten semantics remain
logical evidence; the manifest never invents a physical mapping for decoded bytes.

`recover-ntfs` uses the same record/name/output arguments for supported free-record
candidates. Both the MFT allocation bit and FILE flag must indicate unallocated.
The manifest retains raw FILE evidence, sequence, exact native name, current bitmap
and owner outcomes and observed conflict ranges. Missing bitmap or interrupted
owner coverage stays unknown even when candidate byte extraction completes. This
profile supports resident or single-segment nonresident streams; unsupported
attribute-list-dependent free records fail explicitly.

`inspect-usn` discovers the native `$Extend/$UsnJrnl` namespace, retains `$Max`,
records, rollover/retention observations and gaps. `inspect-logfile` separately
observes supported restart copies; it does not replay transactions or advertise
a complete transaction history. Unsupported namespace/mapping profiles keep their
causal errors instead of silently selecting unrelated raw streams.

`timeline-ntfs` emits both native NTFS timestamp sets; `timeline-fat` uses the same
explicit directory region as `slots-fat`. FAT timezone remains unknown unless
`--utc-offset-seconds N` is supplied. These commands stream source order, preserve
precision and invalid calendar encodings, and emit each timestamp scan's terminal
outcome alongside the enclosing inventory outcome. They do not invent historical
paths or journal associations. Add `--sort --temporary-dir DIRECTORY` for bounded
external chronological sorting; the directory must be held stable by the caller.
Sorted FAT output requires an explicit timezone. Unknown/invalid chronological keys
fail before any sorted timestamp is delivered. Native inventory/timestamp coverage
and outcomes precede the independent sorted-output ordinal coverage and outcome;
serialized event provenance is preserved exactly through sorting.

`timeline-usn` emits validated journal records with their native FILETIME ticks
and independent retention/gap observations. It accepts the same sorting options;
only journal records enter chronological sorting, while namespace and coverage
observations retain their traversal order.

`extract-fat` additionally requires `--slot-offset BYTES --output-dir DIRECTORY`.
It visits the complete selected directory region, builds a qualified live/deleted
alias map, inspects current allocation/ownership and exports through the public
library. A cleared deleted chain requires the explicit `--contiguous-hypothesis`
option for contiguous reconstruction. Output names are generated exclusively;
evidence names remain native manifest data and never become host paths. Files
keep `.partial` suffixes even when all candidate bytes were exported. Standalone
manifests retain raw aliases, reconstruction hypotheses, current conflict/unknown
qualifications, independent map/ownership outcomes and the delivered-prefix hash.
Current free clusters and completed extraction do not prove original contents.
Incomplete ownership checks stay unknown and make the overall CLI return failure.

Every JSONL record declares `version: 1`. Shared coverage events and terminal
outcomes serialize directly from the library. The terminal identifies coordinate
space, requested domain, unvisited remainder, last delivery and causal stop reason.
Acquisition labels are never verified digests; optional manifests separately retain
acquisition times, consistency uncertainty, missing acquired ranges, parent/overlay
inputs and explicit digest domains. Logical disk offsets never claim a physical
container-file mapping.

`source_id` is a process-local token for one bounded source view. Clones keep
the token; selecting another region creates a new token even with identical
acquisition labels. It is not an evidence digest. Candidate export rejects reuse
assessments from a different view.

Human summaries go to stderr. Exit status is 0 for complete requested work, 2 for
an incomplete library scan, and 1 for argument or host/output failure. A missing
terminal record, malformed partial JSON record or failed flush makes an export
incomplete even if a byte hash exists. Multi-phase extraction/timeline output has
one terminal per independent profile; a complete final byte scan does not erase
an earlier incomplete metadata phase.

Host export errors return `ExportFailure`, retaining artifact paths, delivered
prefix length/hash and prior traversal outcomes. Terminal write, flush and sync
failures remain distinct from traversal failures. `terminal_delivered` means the
manifest terminal was durably reported; that terminal may report a data-file
sync failure and does not establish successful extraction.

`--records`, `--read-bytes`, `--output-bytes` and `--memory-bytes` tighten library
ceilings. CLI JSONL output additionally shares one byte ceiling; exclusive export
charges its metadata and bytes against its own output ceiling, with bounded
terminal reporting reserved outside it. Cancellation and gaps remain explicit in
the library contracts. Abrupt process termination can leave no terminal record.

Qualification status and unrun native/release gates are recorded separately in
[integration/forensics/EVIDENCE.md](../integration/forensics/EVIDENCE.md). Host tests
do not establish native Windows behavior, capture consistency or firmware boot.

The independent CLI gate can be rerun against a built example:

```sh
cargo build --locked --all-features --example filesystem-forensics
rustc --edition 2024 scripts/forensics-ntfs-fixture.rs -o /tmp/forensics-ntfs-fixture
python3 scripts/test-filesystem-forensics-cli.py \
  --binary /path/to/target/debug/examples/filesystem-forensics \
  --ntfs-fixture-generator /tmp/forensics-ntfs-fixture \
  --evidence-dir /path/to/fresh/receipt-directory
```

The script requires a fresh evidence directory and retains exact commands, source
and tool hashes, output hashes, JSONL/stderr records and immutable fixture checks.
These hand-authored fixtures test decoder/export behavior; native OS and independent
tool qualification remain separate receipts.
