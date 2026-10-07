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

These APIs do not provide directory/VFAT decoding, metadata preservation,
whole-volume allocation ownership, dirty-state validation, FSInfo-content or
backup-content verification, editing, or recovery. Strict chain reads reject
volumes whose data-cluster identifiers overlap reserved-marker values,
and allocation beyond the
size-derived chain. Geometry success is not a complete FAT support claim.

The primary format reference is Microsoft's FAT specification version 1.03,
December 6, 2000, BPB, type determination, FAT structure and FSInfo sections:
[Microsoft specification](https://www.cs.fsu.edu/~cop4610t/assignments/project3/spec/fatspec.pdf).
Tests use independent hand-built BPBs and packed FAT entries, not production
formatters; native interoperability and fuzz evidence remain future gates.
