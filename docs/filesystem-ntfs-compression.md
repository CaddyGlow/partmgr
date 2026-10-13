# Bounded NTFS LZNT1 reads

`partmgr::fs_ntfs` uses published `ms-compress` 0.1.3 with default features
disabled. The lockfile binds the registry archive SHA-256
`2437237a7839e93e8d1223438c27c2b6d7c58125bdf3dcfd0c18b4881bf25016`.
No local checkout or duplicate LZNT1 implementation is used.

The explicit entry points are `open_stream_with_compression` and
`data_streams_with_compression`. Both take existing `NtfsStreamLimits` plus
`NtfsCompressionLimits { max_unit_bytes, max_units_per_read, max_work }`.
`NtfsDataStream::compressed` describes the selected stream, independently of
the object's default DATA or directory compression policy. Existing strict and
ordinary stream entry points retain their exclusions.

The initial read profile accepts native compression format 1, compression-unit
exponent 4 and 512/1024/2048/4096-byte clusters. Units contain fully allocated
plain bytes, no allocation (logical zeros), or a fragmented allocated prefix
followed by a sparse suffix (packed LZNT1). Unit assembly spans attribute-list
segment boundaries. Native virtual coverage and physical-size accounting,
segment continuity, overlap and prefix ordering are checked before handles are
published. Unknown compression profiles, encryption and reparse/offline objects
remain unavailable. The initial profile requires complete unit allocation
coverage; it does not infer missing runs from EOF.

Reads decode only touched units, reserve two unit buffers through `Resources`,
and enforce per-read unit/extent work limits. They zero uninitialized bytes and
do not read payload for wholly uninitialized requests or zero units. Raw units
are read only through their initialized prefix. The codec is
`ms_compress::lznt1::decompress_storage_unit`, so bytes beyond the required full
unit's validated final chunk are allocation padding rather than another codec
stream. Short output must cover every initialized logical byte; malformed
expansion fails. A failing unit is not copied to the caller; earlier successful
units in the same read may already have been returned in its buffer. Concurrent
reads use independent bounded scratch and retain existing source-length and
cancellation checks. Caller-established source stability remains required.

Independent hand-authored NTFS/LZNT1 tests cover mixed units, exact named streams
on files/directories, fragmented runs, segment boundaries, initialized tails,
malformed data, geometry/accounting rejection, resource limits and cancellation.
They establish portable behavior only. Windows-authored compressed fixtures,
complete native plaintext comparisons and native mount/edit round trips remain
required before qualification. Ownership audits still reject compressed
allocation; this reader grants no mutation or free-space authority.

This implements a decoding prerequisite of N6 in the
[maintenance plan](filesystem-write-maintenance-plan.md). Compressed-unit
encoding/publication, native `$LogFile` recovery and transactional stream writes
remain open. The dependency's encoder is available for that later work; this
change does not create a standalone encoding API or writable support claim.

## Format references

- Microsoft [MS-XCA revision 10.0, 2024-04-23](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/),
  sections 2.5 and 3.3. Retrieved PDF SHA-256:
  `e7806b36adc81b75f50bf57559c55420fcaadeb98a0435e8865d2eb3512d5e9e`.
  Local research archive: `/data/cache/partmgr-maintenance-specs/MS-XCA-20240423.pdf`.
- Linux ntfs3 [native attribute layout](https://github.com/torvalds/linux/blob/v6.12/fs/ntfs3/ntfs.h)
  and [compression-unit allocation](https://github.com/torvalds/linux/blob/v6.12/fs/ntfs3/attrib.c).
  Release tag object: `06090c9b622a7e1f797e775db4c035e0d779b76e`.
  These are implementation cross-checks, separate from Windows qualification.
- [Published codec API](https://docs.rs/ms-compress/0.1.3/ms_compress/lznt1/).
