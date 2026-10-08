# Initial FAT geometry and chain inspection

`fs_fat::FatVolume` retains a bounded immutable `virtdisk::ReadAt` source and
reads only the first 512 bytes during geometry inspection. Family selection
uses data-cluster count. The initial profile validates conventional BPB sizes,
metadata/data bounds, FAT capacity, fixed-root layout, and FAT32 version 0:0,
flags, active-copy selection, root and reserved-area references. Unknown
historical profiles remain rejected rather than inferred from a label.

`open_file` takes explicit first-cluster and length facts. It follows exactly
the required number of clusters and requires an end marker at that boundary,
rejecting cycles and overlong/short chains. It checks mirrored entries unless
a FAT32 active copy is selected. Chain work and maps are bounded; memory
reservations remain owned by the file. Payload reads use an indexed coalesced
map and caller buffers. Cancellation and backend errors propagate.

These APIs do not provide interpreted timestamp metadata preservation,
whole-volume allocation ownership, dirty-state validation, FSInfo-content or
backup-content verification, editing, or recovery. Strict chain reads reject
volumes whose data-cluster identifiers overlap reserved-marker values,
and allocation beyond the
size-derived chain. Geometry success is not a complete FAT support claim.

The primary format reference is Microsoft's FAT specification version 1.03,
December 6, 2000, BPB, type determination, FAT structure and FSInfo sections:
[Microsoft specification](https://www.cs.fsu.edu/~cop4610t/assignments/project3/spec/fatspec.pdf).
Tests use independent hand-built BPBs and packed FAT entries, not production
formatters. Native FAT12/16/32 interoperability and bounded fuzz smoke evidence
are recorded in `filesystem-native-validation.md` and `filesystem-progress.md`;
those receipts establish only their documented profiles and source versions.

Bounded namespace reads now use `root_directory` and `read_directory`, with
explicit scanned-slot and directory-cluster limits. Every slot and chain step
checks cancellation; inventory and bounded LFN scratch retain shared memory
charges. Deleted entries, volume labels and dot links are excluded. Directory
termination bounds inspection; unused tail allocation is deliberately not an
ownership audit. Chains without a terminator are followed with cycle and mirror
checks until EOC or a work limit.

`FatEntry` preserves the exact eleven-byte short alias and original metadata
slot. VFAT names retain exact UTF-16 code units, including unpaired surrogates.
Ordinal order, checksum, type, cluster-zero fields, terminator/padding and the
255-unit length limit are strict. Lookup compares exact native representation;
OEM codepage decoding and FAT case-insensitive equivalence are unavailable.
`open_entry` returns a reusable `FileRead` handle retaining the source-scoped
slot identity. Entries from another volume open are rejected. These interfaces
do not establish snapshot isolation, global allocation ownership, writable
support, or a faithful metadata-copy policy.

The immutable facade and the owned editor share one internal decoder and audit
implementation. The decoder accepts either an immutable `ReadAt` source or a
borrowed `Storage` session through a separate internal positional-read trait.
The session variant does not implement `ReadAt`, retain the backend, or create
deferred file handles. It returns owned checked maps with retained memory
reservations. The editor can therefore inspect allocation and namespace under
its existing exclusive storage ownership without manufacturing an immutable
source contract for mutable media.
