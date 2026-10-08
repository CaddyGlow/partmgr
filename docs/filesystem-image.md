# Common immutable read-profile facade

`fs_image::ReadImage` opens one explicit `ReadOptions` profile and implements the
common `TreeSource` contract. It dispatches to the existing checked FAT12/16/32,
classic ext2, clean single-FAT exFAT1.00, NTFS3.1 native-index and XFSv5
leaf-tree/inline-extent/shortform-directory, classic HFS, HFS+/HFSX, logical NOR JFFS2 and bounded Linux JFS engines. It adds
no filesystem codec and does not expose mutable storage. Unsupported families,
advanced features, optical integration and write dispatch remain separate work.

`probe` reads at most the first512bytes and the two-byte ext signature at1080.
Its leased result contains candidate signatures only. Multiple candidates are
returned without selecting a winner. Empty results mean no implemented
signature matched, not that the source contains no filesystem. Signature matches
can be malformed or refer to unsupported features. Opening selects exactly one
engine and never retries another engine after failure.

The caller supplies a bounded immutable `virtdisk::ReadAt`, typically a
`DiskView` over an explicitly selected region. Region selection, container and
partition ownership remain outside this module. Sources must remain stable for
planning and all deferred access; the facade reports caller-guaranteed stability,
not a snapshot. The source length is checked before/after forwarded accesses.
Opened stream wrappers keep those checks and cancellation active even on empty
or EOF reads after the image handle has been dropped. Same-length external
mutation remains outside the immutable source contract.

`AllocationPolicy::RequireClean` completes the selected profile's allocation,
reference and state audit before retaining its namespace. Any finding,
incomplete accounting, exhausted bound or audit error fails opening.
`MetadataOnly` is an explicit inspection policy and grants no ownership proof.
`allocation_evidence()` distinguishes a completed clean profile audit, a
supported audit not requested, and an unavailable complete audit. NTFS now uses
the bounded base-record allocation/reference audit before RequireClean inventory;
MetadataOnly records NotRequested. A clear NTFS volume flag alone is not a
complete audit. Native reserved
root exclusions require `NtfsTreePolicy::UserNamespace`; Complete remains the
default policy available to the caller and rejects unavailable system streams.

The capability report describes the actual selected read profile. Read and
payload decoding are available for that profile. A separate allocation audit
is conditional where implemented; its availability is distinct from opening
evidence. Missing operation entries are unsupported. The read handle grants no
build, replace, create, truncate, delete, rename, flush, publication, discard,
recovery or firmware capability. Runtime validation-evidence strings are empty;
this handle does not manufacture a native receipt for the caller's source.

Profile, source-guard and opened-file-wrapper allocations retain shared budget
leases. Each engine retains its own inventories/maps through the same pool;
payloads remain deferred and use caller buffers. The facade does not account for
memory independently allocated by a caller's backend or establish a unified
container cache budget. Cancellation, stale length, exhausted reservations and
causal source errors propagate; failed openings refund retained allocations.

`tests/fs_image.rs` uses independent FAT12, classic ext2, archived exFAT and NTFS
index, complete-allocation and independent XFS fixtures to exercise all five
dispatch routes, required/omitted
audits, lost allocation rejection, exact native hard-link relationships,
valid-data zero tails, the separate NTFS clean-audit and namespace policies,
retained reads, cross-source identity rejection,
length changes at EOF, cancellation and I/O/budget errors. Root package tests
include their fixture sources and bytes without needing the excluded fuzz
workspace. These tests validate dispatch and contracts; independent engine
receipts remain in each format's evidence document. Writer/backend dispatch,
remaining families and published partmgr API acceptance remain open.

The focused packaged facade gate passed from
`/data/cache/partmgr-package-tests-iaj9e383/partmgr-0.1.0` using published
registry dependencies and six tests. `scripts/filesystem-package-check.py`
packages and extracts a fresh source snapshot, checks dependency provenance,
then runs formatting, all-target/all-feature locked Clippy and all-feature locked
host tests, retaining command logs, source/package/lock/binary hashes and a
terminal receipt. Its first whole-package run caught intermediate unused NTFS
audit primitives while that engine was being extended; that failure is retained
in `/data/cache/partmgr-package-gate-fjlqzdxy/evidence.json`. A clean full snapshot
passed after the implementation freeze at
`/data/cache/partmgr-package-gate-ejoaoxvr/evidence.json`: all packaged formatting,
Clippy and host tests passed using registry virtdisk0.2.0. This snapshot includes
seven facade tests and the shared complete NTFS fixture, preceding the XFS route
and flash contract additions. A fresh package snapshot must cover later changes.
Packaging does not
publish the crate or prove compatibility with portable targets.

## APFS offline reauthoring

The APFS facade can also supply the native offline `ApfsBuildPlan` tree input.
The integration regression reopens the emitted image through the same facade,
checks report-bound complete clean audit, sparse logical bytes and the embedded
resource fork, and keeps both streams usable after dropping the facade.
Changed source length rejects retained EOF reads. Explicit builder defaults
transform source metadata; this pipeline does not establish in-place COW editing.

## JFFS2 declared logical NOR dispatch

`ReadOptions::Jffs2Compressed` additionally requires explicit
`Jffs2CompressionLimits`. It permits bounded RTIME/ZLIB nodes alongside
NONE/ZERO and decodes requested node ranges lazily without a retained payload
cache. Both allocation policies require complete clean reconstruction/audit.
Malformed compressed history and expansion beyond the supplied caps reject
opening. The original `Jffs2` option retains its strict NONE/ZERO profile.
Retained files preserve source-length and owner-cancellation guards; temporary
decode buffers and decoder workspace are charged and refunded per operation.
This is immutable read access and grants no compressed editing authority.

`ReadOptions::Jffs2` requires caller-supplied FlashGeometry and Jffs2Endian plus scan/reconstruction and namespace audit limits. The bounded probe recognizes first-node LE/BE magic only; erased prefixes or later nodes are not scanned by probing. Geometry is never inferred. Inventory always performs the complete supported scan/namespace audit, so both allocation policies report CleanProfileAudit on successful opening. This evidence describes logical reconstruction and informational erased blocks; it grants no erase, GC, discard or hardware authority. Ten facade tests now include both byte orders, native names, hardlinks, unfollowed symlinks, historical deletion and retained EOF/cancellation guards.

`ReadOptions::HfsPlus` selects the bare nonjournaled HFS+/HFSX reader with explicit
B-tree, extent and ownership limits. `ReadFormat::HfsPlus` is only a header
signature candidate at offset 1024; opening validates the catalog comparator
rather than inferring case behavior from that signature. Native data and resource
forks remain separate streams. Inventory requires a complete clean ownership
audit even under MetadataOnly, so successful opening reports CleanProfileAudit.
The initial profiles use HFS+ ASCII folding or actual HFSX binary UTF16 comparison;
unsupported Unicode folding, journal, populated attributes and hardlink indirection
remain engine errors. This interface conveys no mutation authority.

`ReadOptions::Hfs` explicitly selects the classic HFS reader with bounded native
comparison and exact byte names. The `BD` master-directory-block signature at
1024 is a candidate only, distinct from HFS+/HFSX. Inventory always requires a
complete clean profile audit. Data/resource forks remain separate streams; the
initial comparator profile rejects unsupported punctuation/extended native
collation instead of guessing host case behavior. Classic HFS remains under
native validation and does not confer mutable filesystem support.

JFS options require explicit decoder and allocation/reference audit caps.
Inventory always audits the implemented profile under both allocation policies;
`allocation_evidence()` reports that actual clean proof. Its signature candidate
is the primary superblock magic at offset 32768 and does not establish support.
Exact UTF16 names, hardlinks and sparse/unwritten data remain native common-tree
semantics. Broader JFS features and journal replay remain gated by the engine.

`ReadOptions::Ext` explicitly selects supported immutable ext2/ext3/ext4 profiles
with caller-supplied audit, object, entry, mapping and directory bounds.
`ReadOptions::Ext2` retains its classic contract and rejects journal-bearing or
extent-enabled geometry. Accepted extent profiles report `Family::Ext4`, while
classic maps with an inactive journal report `Family::Ext3`. This selection
does not grant editor authority; owned editing retains its classic profile gate.

APFS options select a native volume object identifier explicitly within the
bounded container. Checkpoint/object and allocation/reference audit limits are
separate caller inputs. The implemented profile must pass its complete audit
before inventory under either allocation policy; NXSB recognition alone grants
no allocation proof. Native byte names and resource forks remain distinct.
Broader APFS profiles and native acceptance remain engine-specific work.
