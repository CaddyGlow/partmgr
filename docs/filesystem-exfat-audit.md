# Read-only exFAT ownership audit

`audit_exfat` builds complete allocation evidence for the strict clean, single-FAT revision-1.00 profile supported by `ExfatVolume`. It reuses the checked boot, system-stream, chain, entry-set, up-case and native-name codecs. It does not grant write, discard, compaction or recovery authority. Callers must stabilize the backing source for the entire audit; positional reads and source-length checks do not establish a snapshot.

The [Microsoft exFAT specification](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification), sections 3.1.18, 4.1, 5.1, 6.3.4.2 and 7.7, supplies the allocation distinctions: the bitmap records allocation state, chained objects interpret FAT links, contiguous NoFatChain objects do not interpret their FAT entries, and PercentInUse describes the allocated cluster percentage rounded down.

The audit claims every validated root/bitmap/up-case cluster and every reachable file/directory allocation. File ownership covers DataLength, including allocation beyond ValidDataLength. Every directory also rejects duplicate exact or folded native names using fallibly reserved canonical UTF-16 hash keys derived from the validated full up-case table. This avoids quadratic pairwise comparison; the directory slot bound also bounds total name units and key storage. A root collision fails without a report; a descendant collision produces incomplete evidence. It detects shared clusters, repeated or overlapping directories, references to bitmap-free clusters, allocated clusters without reachable owners, unowned bad markers with free bitmap bits, and a known main-boot PercentInUse mismatch. Unowned allocated bad markers count separately from lost allocations; stale ordinary links in bitmap-free clusters do not create ownership. Bad markers inside owned contiguous allocations are ignored along with their other invalid FAT contents. Counters include namespace objects (implicit root included, system streams excluded), distinct owned clusters, bitmap allocated clusters, unowned bad clusters and charged work.

A malformed descendant allocation or directory produces an `InvalidObject` diagnostic and an incomplete report. Any overlapping visited directory produces `DuplicateDirectory`; the audit does not revisit its descendants. Incomplete reports do not claim that unowned bitmap allocations are lost, because unexplored descendants may own them. Strict boot/root/system failures, unsupported profiles/extensions, backing I/O errors, cancellation and exhausted bounds return an error without a report. Unsupported profiles remain unsupported even when the operation would only read them.

`free_ranges` is populated only when namespace traversal and heap reconciliation finish with no findings. These ranges cover unallocated clusters inside the heap, excluding boot/FAT regions and excess volume tail. Every diagnosed inconsistency or incomplete traversal suppresses all ranges. A clean report is evidence for the observed caller-stabilized source; subsequent mutation invalidates that evidence.

## Bounds and validation

The caller supplies `ExfatReadLimits` for checked bootstrapping and individual allocation/directory decodes, plus `ExfatAuditLimits` for heap clusters, aggregate namespace objects, aggregate directory slots, cluster/slot work and retained findings. Both profiles share `Resources`. Attempted malformed allocations and directory scans consume work before decoding; owner visits and complete bitmap reconciliation also consume work. Decoder reservations cover retained directory inventories and temporary maps; the audit separately reserves owner/free-range arrays, queue overhead and bounded diagnostics. The report retains its reservation until dropped.

```sh
cargo test --test fs_exfat_audit --all-features --locked
cargo clippy --test fs_exfat_audit --all-features --locked -- -D warnings
```

Six portable tests use an independently encoded 2 MiB fixture, not a production builder. They cover a fragmented file, contiguous file with an uninitialized tail, nested directory, free-range totals, file/system/directory cross-links including an overlap after a different first cluster, lost bitmap allocation, referenced free allocation, bad markers, stale FAT entries, PercentInUse, malformed descendants, cancellation, limits and reservation release.

The explicitly ignored native gate fails when its required tools are missing:

```sh
PARTMGR_EXFAT_AUDIT_EVIDENCE=/data/cache/exfat-audit-evidence \
  cargo test --test fs_exfat_audit --all-features --locked -- --include-ignored
```

`PARTMGR_EXFAT_MKFS` and `PARTMGR_EXFAT_FSCK` may select executable paths. On 2026-10-07, exfatprogs 1.3.2 independently accepted both a real mkfs-produced 64 MiB empty image and the clean independently authored payload fixture. Its `fsck.exfat -n` and the audit both rejected the crosslinked variant. Image byte comparison and before/after SHA-256 establish that the enabled checks made no fixture changes. `/data/cache/partmgr-exfat-audit-20261007/exfat-audit-basic-v1.txt` records exact commands, versions, executable/source/test hashes, image hashes and retained fixture paths.

This profile does not validate payload contents, decode timestamps, support vendor/unknown allocations, mount or repair dirty volumes, support TexFAT, or establish firmware correctness. Native evidence currently covers clean and crosslinked 512-byte-sector images; wider native corruption matrices and a mounted independent allocator oracle remain acceptance work.
