# Filesystem forensics implementation status

The requirements remain those in [the implementation plan](filesystem-forensics-plan.md).
This status does not replace or narrow that plan. The full workstream is incomplete.

The optional `forensics` feature adds portable, read-only evidence APIs without
enabling `std`. Host opening, JSON Lines and file exports require both features.
Strict filesystem readers retain their existing behavior.

The dependency-publication transition currently requests `virtdisk 0.3.1` and
`ms-compress 0.2.1`. Existing passing receipts bind earlier manifests and cannot
qualify these versions. The current focused test invocation stops at dependency
resolution because the registry does not yet list `virtdisk 0.3.1`.
`ms-compress 0.2.1` is now present in the local registry cache. Preserve
the requested versions and rerun locked repository, feature and native gates once
publication and the lockfile update complete.

New audit regressions awaiting that run cover malformed FAT LFN fragments,
overwritten deleted aliases, truncated NTFS volume bitmap uncertainty,
independent FILE/bitmap disagreement, owner conflicts retained after a scan
limit, stale USN sequence references and unmatched rename records. Their source
and formatting review is complete; execution is not yet established.
The next qualification run also covers allocated candidate clusters with no
resolved current owner, host spool write/preparation failures, and deferred
physical-device reads after acquisition revocation. The native regression checks
the original typed causal error and exact unreadable/unvisited coverage after
the normal backend-equivalence assertions.

| Plan step | Current implementation | Outstanding qualification or functionality |
| --- | --- | --- |
| 1. Sources and evidence | Stable acquisition lifetime/revocation, unavailable ranges, bounded-view IDs and coordinate spaces, raw/container/native opening, partition selection, acquisition manifests and causal scan/export outcomes | Published upstream adapter release and qualification against it; hot removal and remaining resource/provenance audit |
| 2. NTFS inventory | Raw/fixup slots, independent MFT bitmap/mirror evidence, volume bitmap, current ownership and extensions; clean and dirty Windows-created fixture qualification | Remaining malformed mapping/coverage combinations and broader device/backend profiles |
| 3. FAT inventory | Raw deleted/LFN/slack slots, each packed FAT copy, bounded independent chain comparisons, typed copy differences, ownership/cross-links/orphans; native FAT12/16/32 tooling comparisons | Broader overwrite/native profile qualification |
| 4. Extraction | FAT live/deleted maps and contiguous hypotheses; NTFS live resident/ADS/sparse/LZNT1 and deleted resident/nonresident candidates; allocation/owner assessments, hashes and exclusive manifests | Deleted attribute-list-dependent recovery remains explicitly unsupported; remaining host failure/metadata budget audit |
| 5. Journals and timelines | Validated USN namespace/$Max/records/retention/gaps, separate LogFile restart observations, both NTFS timestamp sets, explicit FAT timezone, bounded external sorting and JSON spooling; native sorted-USN CLI verification | Ambiguous link/rename profiles and additional native interruption cases |
| 6. Tool and release | CLI inventory/extraction/recovery/journals/timelines and FAT-copy comparisons; versioned JSONL and summaries; compiled feature exclusion gate; current-source native Windows clean/dirty/rollover and Sleuth Kit comparisons; 10,000 deterministic mutations and 1,001 instrumented iterations on earlier bound snapshots | Current-source mutation campaign, published dependency and release qualification |

The candidate extraction API accepts explicitly supplied maps; it does not infer
that a deleted record describes original surviving bytes. `CurrentlyFree` never
authenticates historical content. Missing allocation or ownership evidence remains
unknown. Output hashes describe the exported prefix; completion is recorded
separately in the shared terminal outcome. A missing terminal JSONL record means
an incomplete export.

The stability provider is a lifetime capability supplied by the acquisition
owner. Opening a raw file or physical disk read-only does not provide a snapshot
or detect arbitrary same-size external writes. Providers must actually hold the
artifact/device stable, and deferred readers fail after detected revocation.

Portable tests are not native-device receipts. The upstream physical-disk scripts
and Windows tests require separately provisioned disposable devices. Firmware
evidence remains outside this workstream in the QEMU/OVMF gate.
See [qualification evidence](../integration/forensics/EVIDENCE.md) for attempted
native provisioning and the remaining receipt requirements.
