# NTFS allocation and reference audit

`fs_ntfs_audit::audit_ntfs` performs a bounded, read-only audit of the supported NTFS 3.1 profile. It examines the complete MFT record domain and volume cluster bitmap; it does not apply the tree adapter's optional user namespace exclusions. The report retains its resource reservation until dropped.

The audit compares `$MFT::$BITMAP` with FILE record allocation flags, parses every live base record, and accounts for every supported nonresident attribute, including named system streams. Physical ownership includes allocations beyond logical EOF and uninitialized tails. `$BadClus::$Bad` is handled as the native full-volume bad-cluster stream: its unmarked holes are accepted only for that exact system attribute, with checked virtual length and zero initialized length. Ordinary unmarked holes remain invalid. Bad physical clusters are counted as owned allocations.

Directory references come from checked `$I30` indexes, including allocated INDX blocks and their bitmap, rather than an MFT name scan. Checks include target and parent sequence numbers, FILE_NAME occurrence counts, hardlink counts, native DOS aliases, reachability, directory aliases and cycles. Every live directory is inspected, including unreachable directories. Reserved records 12–15 may lack namespace occurrences. Index allocation and reference work have aggregate limits.

The audit compares full physical ownership with the volume bitmap to identify crosslinks, references to free clusters, and unowned allocated ranges. It independently reports dirty and other volume flags, mismatched MFT allocation bits, missing system records, mirror geometry, canonical USA-fixed `$MFTMirr` records, and the backup boot sector. The USA sequence word may differ between equivalent record copies; protected sector contents must agree. Unused mirrored FILE records are compared without requiring live attributes. A mirror extending beyond the logical MFT record domain is an unsupported profile.

Free ranges are returned only when the report is complete and has no findings. They exclude owned clusters, cluster zero, fractional cluster tails, and the backup boot sector outside the declared cluster domain. An allocated record whose contents cannot be inventoried makes the report incomplete; no free ranges or claims of lost allocations are produced from that partial inventory. Unsupported codecs or structural failures fail the operation instead of yielding a partial free proof. Compression, encryption, attribute lists, unsupported index collations and nonresident directory index bitmaps remain unsupported.

`NtfsAuditLimits` bounds clusters, records, attributes, physical ranges, namespace entries, index blocks, depth, work, findings and returned free ranges. Reservations precede proportional allocations, temporary reservations refund on failure, and cancellation is checked during scanning. Bitmap reads use bounded pages. The audit reads metadata and allocation maps, not ordinary file payloads. Backend errors and source length changes are explicit errors; callers must keep source contents stable for the entire operation because a length check cannot detect an equal-length external mutation.

A clean report is structural evidence for this profile, not a journal replay, hibernation check, durable snapshot, exclusive ownership grant, repair authorization, or permission to write or discard the returned ranges. The operation never edits the image. Callers needing durable or exclusive guarantees must establish those separately.

Independent tests construct boot sectors, FILE/INDX fixups, runlists, bitmaps, system records, hardlinks, sparse files and mirrors directly from bytes in [ntfs_clean.rs](../tests/fixtures/ntfs_clean.rs). Mutations exercise crosslinks, lost allocations, bitmap disagreement, dirty flags, mirror disagreement, cycles, incomplete inventory, unsupported owners, source changes, I/O failures, cancellation, limits and resource refunds.

The explicitly enabled native gate creates a fresh image using `mkntfs`, writes 48 nonresident files using `ntfscp`, and compares total/free cluster counts with `ntfsinfo` and selected payloads with TSK `fls`/`icat`. It requires the tools when enabled and preserves commands, versions, source and executable hashes, stdout/stderr, and unchanged image hashes. Run it with a fresh receipt directory:

```sh
PARTMGR_NTFS_AUDIT_EVIDENCE=/data/cache/partmgr-ntfs-audit-new \
  cargo test --locked --test fs_ntfs_audit native_complete_ownership -- --ignored --nocapture
```

Native evidence demonstrates the exercised mkntfs profile; it does not establish support for arbitrary Windows-created NTFS volumes or recovery-required images.

The frozen audit receipt is `/data/cache/partmgr-ntfs-audit-native-20261008-final/receipt.txt`: 16,383 clusters, 2,235 owned/allocated clusters, 14,148 free clusters, 67 allocated records and 263 attributes, with no findings. The namespace and direct ISO/UDF capture gates were rerun against the same reader at `/data/cache/partmgr-ntfs-tree-native-20261008-audit-frozen/receipt.txt` and `/data/cache/partmgr-ntfs-optical-native-20261008-audit-frozen/receipt.txt`.
