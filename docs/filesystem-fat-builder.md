# Staged FAT authoring

`FatBuildPlan` authors a new, unpublished FAT12, FAT16 or FAT32 image through
exclusive `Storage`. The caller supplies its exact existing byte length and
retains exclusive access until emission and verification finish. Publication is
an independent caller operation. This API must not be used to edit an existing
filesystem: it initializes the entire supplied region, including free space.

The compatibility `new` profile contains root regular files with canonical
uppercase ASCII 8.3 names. `new_tree` additionally accepts nested directories
and exact UTF-16 VFAT components, including unpaired surrogates. Stable
source-scoped identities bind parent relationships; duplicate identities and
hard links require a separate explicit transformation and are rejected.
Directory entries carry no payload source; files use immutable direct `ReadAt`
sources. Missing parents, cycles, invalid components, ASCII case collisions,
files above the FAT u32 length limit and insufficient capacity fail preflight.
The caller must select `FatTreeMetadataPolicy::DeterministicDefaults`.
It copies no source ownership, timestamps, ACLs, links, named streams or unknown
metadata, and does not claim faithful tree capture or bootability. Authored
creation/write dates are deterministic 1980-01-01. No executable boot code is
installed; FAT boot signatures describe format geometry only.

Geometry uses 512-byte sectors, caller-selected power-of-two clusters up to
32 KiB, two identical FAT copies and a 512-entry fixed FAT12/16 root. FAT32
reserves 32 sectors, starts its growable contiguous root at cluster 2, and emits primary
and backup boot/FSInfo sectors with exact free-cluster hints. The chosen family
must agree with the actual data-cluster count. Sorting short names (compatibility profile) or native component paths (tree
profile) makes allocation and bytes independent of input inventory order; the
caller supplies an explicit volume serial number. Directories are allocated
before files, each with contiguous chains. Subdirectories contain canonical
`.` and `..` entries; root parents use cluster zero, including FAT32. Directory
space includes a zero terminator and grows beyond one cluster when needed.

Tree names compare with ASCII case folding only; non-ASCII UTF-16 units compare
exactly. This is an explicit narrow namespace policy, not Unicode case
compatibility. Uppercase canonical 8.3 names retain their short spelling. Other
names receive deterministic uppercase `~n` aliases and VFAT slots, reserving
canonical aliases first and avoiding collisions with both aliases and native
names under the stated comparison. UTF-16 is never converted through lossy
display text. Trailing space/dot and reserved FAT punctuation are rejected.

Planning retains a shared-memory reservation for its owned inventory and checks
that two 64 KiB scratch buffers fit. Emission reserves this scratch again before
mutation, allowing other consumers to exhaust the pool safely between planning
and emission. Payload sources implement immutable positional `ReadAt`; their
bytes must remain stable until verification completes. The caller guarantees identity/generation stability: this inventory API does
not query an external tree provider to revalidate identities. Length is checked before
and after emission. A whole-image digest additionally detects source byte
changes observed between writing and verification; this is detection, not
snapshot isolation. Source and destination must not alias.

Every output byte is initialized and streamed with bounded scratch. Short writes
are completed; zero or excessive write counts fail. One durable flush follows
all writes, then the complete image is regenerated and read back byte for byte,
including FAT mirrors, directories, payload, padding and free space. The report
contains verified length and SHA-256. Backend `flush` must provide the durability
promised by `Storage`; verification cannot prove dishonest backend guarantees.

Preflight failures leave storage untouched. Failures or cancellation after a
write attempt return `InterruptedWrite`, retaining an underlying I/O error when
available and reporting whether the flush completed. A failed flush returns
`UncertainDurability`. Staging must remain unpublished after any error; inspect
or discard it before retrying. No rollback or existing-volume recovery is
advertised. Independent `fsck.fat` and mtools evidence belongs to the native
filesystem gate; host self-readback does not establish firmware correctness.
