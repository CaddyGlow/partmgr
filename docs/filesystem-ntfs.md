# NTFS 3.1 strict baseline reader

The additive [DATA/ADS and attribute-list profile](filesystem-ntfs-streams.md)
now provides bounded exact named-stream reads and native attribute/timestamp
views. Generic metadata also retains the STANDARD_INFORMATION MFT-change
timestamp as `ntfs.STANDARD_INFORMATION.mft_changed.FILETIME`: eight exact
little-endian FILETIME bytes (1601 UTC epoch, 100 ns resolution). It remains
distinct from content modification and access timestamps. This addition does
not establish complete metadata capture or native security restoration.

`partmgr::fs_ntfs` opens actual NTFS volumes through `ReadAt`. This first reader slice implements boot geometry, indexed MFT reads, USA-protected base FILE records, native FILE_NAME occurrences, and resident or nonresident unnamed DATA. It advances the NTFS disk-capture prerequisite; [Native directory-index traversal and policy-scoped TreeSource](filesystem-ntfs-tree.md) now provide the next slice, with a [separate content-only optical gate](filesystem-ntfs-optical.md). A separate [complete bounded base-record allocation/reference audit](filesystem-ntfs-audit.md) now validates supported-profile ownership. Complete system-stream capture, advanced profiles and mutation remain future work under FILESYSTEM_PLAN.md.

Supply the exact volume region, immutable for the entire volume/record/file lifetime, `NtfsReadLimits { attributes, runs, names }`, and shared `Resources`. `NtfsVolume::open` requires NTFS 3.1 VOLUME_INFORMATION with every volume flag clear. Dirty, upgrade, repair, and other flagged states fail as `Unsupported`; no replay or clean-marker rewriting occurs. A clear marker establishes this selected profile only. Ordinary reader opening does not validate the journal, hibernation state, allocation ownership, mirror or every record. Native directory traversal validates indexes when requested; the separate full-profile audit validates ownership and mirrors without granting journal replay or mutation capability.

The initial geometry supports 512-byte sectors, power-of-two clusters up to 64 KiB, and power-of-two FILE/index record sizes from 512 bytes to 64 KiB. Signed record-size encodings are checked before shifts or allocation. Declared volume bytes bound all physical runs; container tails are excluded. MFT bootstrap comes from the boot-declared cluster, then its complete base-record unnamed DATA mapping drives record reads. The MFT must have initialized, nonsparse data and complete record coverage. Attribute-list-dependent MFTs fail closed.

Each FILE record validates its signature, record number, allocated flag, sequence, base reference, used/allocated sizes, USA array bounds and every sector trailer before attribute interpretation. Attributes require ordered recognized types, unique IDs, checked name/value/run ranges, and a terminator within the used record. Mapping pairs decode signed relative LCN deltas with checked VCN and physical bounds, reject zero runs, unterminated or inconsistent virtual/physical allocation coverage, and reject overlapping physical allocations within a stream. Sparse runs become `Hole`; recorded bytes after initialized length become `Unwritten`. Both return logical zero without reading their backing storage. Recorded initialized extents read through the indexed positional map; opening a nonresident file reads metadata rather than its full payload.

`record(number)` retains all exact UTF-16 FILE_NAME units, including unpaired surrogates, native namespace selectors and parent record/sequence references. Names are occurrences from FILE metadata, not a reconstructed namespace or directory-index oracle. `open_file(number)` opens the current allocated record. `open_object(id)` additionally validates source scope and sequence generation, rejecting recycled or foreign IDs. Source length changes fail as stale; same-length content changes cannot be detected generically, so callers must hold source stability. Handles implement `Send + Sync`, retain their source and resource lease, and survive dropping the volume.

Compressed/encrypted attributes, compression units, extension records, ATTRIBUTE_LIST, split unnamed DATA, named DATA, reparse files and offline files fail explicitly. This slice does not silently discard alternate streams. Standard information timestamps retain raw FILETIME ticks, the 1601 UTC epoch and 100 ns resolution. Native file flags are retained verbatim. Security descriptors, ownership, reparse interpretation and other unimplemented metadata classes are `Uninspectable`; no POSIX permission or ownership conversion is claimed.

Limits bound attributes, native names and encoded runs independently. Reservations precede record scratch, metadata and map allocations. Record/name leases remain live with records; MFT and file map leases remain live with their respective handles and refund on drop or failure. Capacity arithmetic is checked and vectors reserve fallibly. Cancellation is checked before reads, between record sectors/attributes/runs and on deferred reads, including EOF. The indexed map permits at most two logical extents per encoded run after initialized-length splitting. There is no payload cache or arbitrary full-file allocation in the reader.

The layout references are the pinned Linux v6.17 NTFS3 [native structures](https://github.com/torvalds/linux/blob/v6.17/fs/ntfs3/ntfs.h), [mapping-pair implementation](https://github.com/torvalds/linux/blob/v6.17/fs/ntfs3/run.c), and [record fixup implementation](https://github.com/torvalds/linux/blob/v6.17/fs/ntfs3/fsntfs.c). The reader is independently implemented; deterministic byte fixtures are hand-authored separately from production parsing.

Run ordinary fixtures with:

```sh
cargo test --locked --test fs_ntfs
```

The separately enabled native gate requires `mkntfs`, `ntfscp`, `fls`, `icat`, and a fresh evidence directory. Missing tools or environment fail the enabled test. For example:

```sh
nix-shell -p ntfs3g sleuthkit --run 'PARTMGR_NTFS_EVIDENCE=/data/cache/partmgr-ntfs-native-new cargo test --locked --test fs_ntfs native_mkntfs_tsk_oracle -- --ignored --nocapture'
```

The gate formats a 64 MiB image with 4 KiB clusters, copies a 13-byte resident file and a 131089-byte nonresident file, compares whole and selected positional reads against host bytes and independent Sleuth Kit `icat`, and checks exact native names. It verifies the image SHA-256 before and after read-only validation. Receipt files retain commands, tool/source/test-binary hashes, versions, platform information, separate raw stdout/stderr, per-file hashes and status. The successful local receipt is `/data/cache/partmgr-ntfs-native-vdisk02-20261008/receipt.txt`. It establishes the selected clean native fixture only; it does not establish complete NTFS capture, repair, Windows servicing, or firmware behavior.
