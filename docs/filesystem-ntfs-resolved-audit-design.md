# Resolved NTFS ownership audit implementation design

This records the design and implementation boundary for N1 in
`filesystem-write-maintenance-plan.md`. The additive `audit_ntfs_resolved` and
`audit_ntfs_resolved_detailed` entry points implement the bounded plain/sparse
profile below. `directory_resolved` shares the existing index traversal with
resolved attributes and initialized nonresident bitmaps. Native qualification
and the broader N1 requirements remain separate. Source references name
functions instead of unstable line numbers.

## Existing reusable checks

`fs_ntfs_stream::resolve_stream_record` loads a complete base record and bounded
extension records. It verifies list targets by record sequence, attribute
instance, type, exact UTF-16 name, and lowest VCN. It rejects duplicate targets,
unlisted loaded attributes, recursive extension lists, and a mismatched extension
base reference through `RecordProfile::Extension`. The base ATTRIBUTE_LIST can
be resident or one nonresident value; split/multiple list values are excluded.

The shared `native_map` assembler used by `stream_content` groups occurrences by type/name, requires VCN0, validates
contiguous segment coverage and residency/flags, preserves initialized-size
semantics, rejects physical overlap within a stream, and checks sparse physical
accounting. It retains full native extents and physical occurrence claims before
logical clipping. Logical content extents remain clipped to data size and cannot
substitute for allocation ownership beyond EOF or initialized size.

`NtfsNativeAttribute` already preserves both base owner and carrying FILE record,
sequence, instance, fixed-up offset, exact name, flags, and encoded occurrence.
Those are the required distinct provenance dimensions.

`fs_ntfs_audit::audit_ntfs` currently opens the audit profile, parses each live
slot using `volume.record`, accounts its individual nonresident attributes, and
uses `volume.directory` for namespace validation. This is a base-record profile:
extension slots cannot be treated as independent files or simply ignored.
`directory` retains its resident index bitmap restriction; the explicit
`directory_resolved` profile accepts initialized nonresident bitmaps.

## Smallest complete feature slice

The separately declared resolved audit profile supports the existing
bounded ATTRIBUTE_LIST forms, every plain/sparse segmented native allocation,
and resolved `$I30` attributes with resident or nonresident bitmaps. Preserve the
existing strict audit API until this profile is qualified. Compressed/encrypted
attributes and split ATTRIBUTE_LIST values remain explicit unsupported results;
they cannot produce a complete ownership report. This slice advances N1 but
does not complete all N1 or authorize a writer.

1. Extend bounded FILE-slot inspection to return in-use state, sequence, and
   base reference, validating framing/fixups before relying on a nonzero base
   reference. Store classification for all slots under aggregate limits.
   A nonzero reference classifies an extension, not a separate namespace object.
2. Resolve each live base exactly once. Register every participating extension
   slot against the exact owner reference. Require a live allocated matching
   base and matching extension sequence/backreference. After resolution, every
   live extension must have participated exactly once. An unlisted orphan,
   free-listed extension, stale owner, or multiple-owner claim prevents complete
   accounting; do not infer an owner from physical proximity.
3. Extract a shared validated native attribute-map assembler from
   `stream_content`. Its result must retain all physical runs before logical
   clipping, native lowest/highest VCNs and occurrence provenance, logical/data/
   initialized sizes, sparse accounting, and decoded run work. Use it for both
   content reading and ownership, so accepted segment semantics cannot diverge.
   Group streams by base identity, type, and exact name; retain carrying record
   plus instance/offset for each physical claim. Account the base list's own
   allocation exactly once even when omitted from its list entries.
4. Feed physical intervals to the existing global overlap/bitmap sweep once per
   occurrence. Sparse holes claim no clusters; allocated unwritten portions do.
   Preserve `$BadClus:$Bad` special handling by logical base record identity,
   not extension carrier number. Duplicate list entries are malformed references,
   not additional allocations. Cross-stream physical duplicates remain overlap
   findings, including duplicates between two segments in different owners.
5. Assemble resolved `$INDEX_ROOT`, `$INDEX_ALLOCATION`, and `$BITMAP` with the
   same map engine. Refactor traversal to consume these values while retaining
   existing bitmap-tail, child VCN/range/cycle, unreachable allocated index-block,
   USA, entry bounds, and UpCase checks. Require initialized, nonsparse bitmap
   content before interpreting allocation bits. Extension FILE records contribute
   FILE_NAME occurrences to their base's names and timestamps, never independent
   hardlink counters. Compare directory references to base object identities.
6. Read `$MFT` bitmap and volume `$Bitmap` through resolved attributes. Reuse the
   bounded bootstrap for expanded `$MFT`; do not require an extension record to
   be readable through an extent that has not yet been proven by bootstrap.
   Keep mirror comparison over physical FILE slots, distinct from logical
   base-object assembly. Keep source identity checks before and after the audit.

Reserve classification, participation, selected segments, map runs, bitmaps,
intervals, and directory work under Resources. Aggregate extension/list/map work
across the volume instead of refreshing limits for each owner. Cancellation,
invalid mapping, and budget exhaustion must release every reservation and must
not return a complete report. A clean allocation result alone must not claim
capture, security resolution, replay, or mutation readiness.

## Acceptance evidence still required

Synthetic tests can extend `ads_fixture` and the bootstrap fixtures in
`tests/fs_ntfs.rs`, but need whole-volume allocation/MFT bitmaps and namespace
records to exercise the complete audit rather than isolated stream reads.

| Case | Required observation |
| --- | --- |
| Resident ADS in extension and two-segment nonresident ADS | One logical owner; every physical cluster claimed once |
| Orphan extension, stale base/extension sequence, wrong backreference | Rejected or explicitly incomplete; no free-space authority |
| Duplicate list target and unlisted extension occurrence | Rejected before complete report |
| Repeated instance number in different carrying records | Valid when exact list bindings differ; no accidental deduplication |
| Cross-owner physical overlap, free bitmap bit under continuation | Existing overlap/free-owner finding includes exact occurrence provenance |
| Sparse continuation and allocated bytes past initialized size/EOF | Only physical runs claim clusters; no loss through content clipping |
| `$BadClus:$Bad` continuation in extension | Reserved bad allocation retains system-owner semantics |
| Segmented/nonresident `$I30` bitmap and index allocation | Native traversal agrees with independent oracle, including tail/cycle mutations |
| Extension in expanded MFT and resolved MFT bitmap | Bootstrap and whole-volume record enumeration agree |
| Resource/cancellation failures at each new phase | No leaked reservations and no complete report |

The existing ignored `native_ads_attribute_list_independent_oracles` and
`native_mft_attribute_list_bootstrap_matches_independent_dump` establish narrower
reader evidence only. A new native whole-volume gate must use externally
generated extension records, segmented ADS, nonresident index bitmap, sparse
allocation, and hardlinks; save independent native/TSK record and allocation
inventories plus exact image/source hashes. Enabling the gate without required
inputs must fail. Passing host fixtures does not replace Windows filesystem or
firmware qualification required by the maintenance plan.
