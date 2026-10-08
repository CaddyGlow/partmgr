# NTFS implementation priority

The first-priority requirements in `FILESYSTEM_PLAN.md` are Windows snapshot
acquisition, complete native metadata, ACL inspection/preservation/restore, and
forensic extraction, timelines and recovery.
Full NTFS support remains incomplete. This checkpoint separates implemented
decoders from volume capture and native Windows qualification.

| Area | Current checkpoint | Required next evidence |
| --- | --- | --- |
| USN | Borrowed V2/V3 decoder and source-bound selected `$J` extraction; sparse/unwritten/padding events, 13 focused tests and native named-stream comparison | Authenticated journal namespace, `$Max`/rollover handling, timelines and actual Windows journal fixtures |
| Security descriptors | Public `fs_ntfs_security` preserves descriptor bytes, owner/group SIDs, ordered ACEs, unknown payloads and absent/null/present ACL distinctions; three focused tests and integrated strict Clippy pass | Volume-bound `$Secure` lookup and native descriptor comparisons, capture/restore/edit profiles |
| `$Secure` | Bounded `$SII`/`$SDH` tree lookup, `$SDS` copy/hash validation and file-bound metadata capture integrated; native allocated-index gate independently passes for 514 descriptors | Extension-record security resolution and Windows restore/edit qualification |
| Streams and metadata | Exact DATA/ADS enumeration/open and bounded attribute-list/extension resolution integrated; native attribute provenance and distinct SI/FILE_NAME timestamp views retained; 26 focused reader/audit/tree tests plus strict Clippy/fmt pass | MFT attribute-list bootstrap and complete resolved tree/audit paths; compression/encryption and complete capture |
| Snapshots | Windows VSS integration is being implemented in isolation | Actual requester lifecycle, writer/consistency status, stable shadow-volume access and independently qualified Windows acquisition/capture |

The record-only NTFS metadata reader reports security and ownership as
uninspectable. The explicit `fs_ntfs_metadata::inspect_ntfs_native_metadata`
volume-aware path resolves and binds security to the FILE identity; consuming
`into_metadata` attaches exact native descriptor and owner SID bytes under
retained budget accounting. A standalone descriptor parser does not bind an ACL
to a file or authorize native restore. NTFS complete
capture must account for reserved system objects and every stream/metadata class;
the existing selected user namespace and content-only capture do not satisfy it.

The public security parser also passes an adversarial test covering all 256
replacements at each byte of a 60-byte descriptor (15,360 cases). Every accepted
descriptor is traversed through SID, ACL, and ACE views, and all memory charges
refund after success or rejection. Formatting and integrated all-target strict
Clippy pass for this addition. This robustness evidence does not replace native
Windows descriptor or `$Secure` qualification.

The isolated ADS native v3 receipt at
`/data/cache/partmgr-ntfs-stream-native-20261008-v3/verification.json` qualifies
21 streams, including a real nonresident attribute list and extension records.
Every payload was compared with ntfscat and TSK icat; the largest ADS has 131,089
bytes. Root independently checked all 202 artifact hashes and verified that the
three imported implementation/test files match the receipt's source hashes.
This historical native closure predates the core budget transformation helper;
the integrated focused checks qualify the current import separately.

The security native v3 receipt at
`/data/cache/partmgr-ntfs-security-native-v3/qualification.json` covers exact
resident and nonresident per-record descriptors and an actual indexed `$Secure`
ID. Root independently verified all 75 artifact hashes. Twenty integrated
focused reader/security tests, formatting and strict Clippy pass. A new full
host check completed at
`/data/cache/partmgr-ntfs-security-integrated-fullhost-v1.log`: 657 passed,
zero failed and 78 ignored across 80 suites. That compiled checkpoint predates
the foreign-record binding test and opt-in ACL tree capture. Native Windows
snapshots, full capture, ACL restore and editing
remain unqualified.

`NtfsTreeSource::with_security_capture` now enables exact descriptor and owner
SID capture through the volume-aware metadata path. It first resolves security
for every inventoried object; unknown security and cancellation fail explicitly
and refund retained resources. Seven tree tests and three security lookup tests
pass, including hardlinked-file descriptor preservation and foreign-source
identity rejection. The selected namespace retains its explicit exclusions.
The source-bound native receipt at
`/data/cache/partmgr-ntfs-acl-tree-native-v4/qualification.json` compares root and
file descriptors and owner SIDs with native ntfscat output. All 26 artifact hashes
and both imported tree files were independently checked. This is a bounded native
capture profile, not complete-volume capture or Windows restore qualification.

Root separately qualified the additive allocated-index native test against the
current integrated reader in
`/data/cache/partmgr-ntfs-allocated-root-review-v1`. Three ordinary security tests,
all-target strict Clippy and the enabled native gate pass. The new receipt at
`/data/cache/partmgr-ntfs-allocated-root-native-v1/qualification.json` binds 13
compiled source files and 3,158 artifacts; all 514 descriptors match independently
extracted native SDS bytes and their mirrors. The native test is now integrated.
This receipt does not qualify the newer
isolated extension-aware lookup or native Windows behavior.

The combined import was qualified in
`/data/cache/partmgr-ntfs-object-root-review-v1`: revised bounded split-MFT
bootstrap, native attribute selectors, and extension-aware security lookup,
composed with the live ACL tree implementation. Root verified the four revised
bootstrap source hashes; 36 focused tests, formatting and all-target strict Clippy
pass. The separately rerun native allocated-security receipt at
`/data/cache/partmgr-ntfs-object-root-native-v1/qualification.json` binds 14 source
files and 3,159 artifacts with 514 exact descriptor comparisons. That native
fixture has an ordinary MFT; portable split-MFT tests do not establish native
split-MFT qualification, complete ownership, or complete-volume capture.
Six source/test files are now integrated, with prior files and exact import hashes
retained at `/data/cache/partmgr-ntfs-object-root-import-v1/import.json`. The live
36 focused tests, formatting and strict Clippy pass. `NtfsVolume::open_stream_profile`
is an explicit bounded MFT-bootstrap profile; the original constructor remains strict.
`open_native_attribute_stream` resolves same-owner native attributes, while
`lookup_ntfs_security_object` and `lookup_ntfs_secure_id_with_attributes` support
extension-aware security under separate stream/security limits. Existing tree
and ownership-audit completeness limits remain. The full-suite run at
`/data/cache/partmgr-ntfs-acl-tree-integrated-fullhost-v1.log` was compiled before
this import and completed with 660 passed, zero failed and 79 ignored across 80
suites. Its adjacent JSON binds the log hash and historical scope. The current
MFT/security production import's first full-suite run lost its handle and stopped
without a terminal result; its partial log remains at
`/data/cache/partmgr-ntfs-object-integrated-fullhost-v1.log` and is not counted as
passed. A replacement uses fixed archived source and saves command exits and
source/log hashes at `/data/cache/partmgr-ntfs-object-fullhost-v2/receipt.json`.
Formatting and strict Clippy have passed; the full test command is still running.
That fixed source predates the selected-USN extraction import, whose focused and
native checks are recorded separately in [the USN documentation](filesystem-ntfs-usn.md).

Native split-MFT reader evidence is now qualified separately at
`/data/cache/partmgr-ntfs-mft-split-native-20261008-v3/verification.json`. Root
independently verified all 96 archived artifact hashes and all production source
bindings against the live code. The native generator creates base DATA VCNs 0..7
and extension-record DATA VCNs 8..18; complete 66,560-byte MFT output matches both
ntfscat and TSK icat after USA normalization. Sequence, parent, listed-VCN and
physical-alias controls reject malformed mappings. The exact additive ignored
native test is integrated; complete extension ownership and tree capture remain
separate work.

The full USN-integration host run is recorded separately at
`/data/cache/partmgr-ntfs-usn-integrated-fullhost-v2.log`. It completed with exit
zero: 646 passed, zero failed, and 76 ignored across 78 suites. The adjacent JSON
binds the log hash and scope. This is host coherence evidence for the compiled USN
integration, not native Windows evidence. Subsequent security exports and the
budget transformation helper are validated separately from that compiled source.

The live shared Nix profile currently fails evaluation on `cargo-xtask`.
Verification uses the retained same-lock Rust 1.99 profile at
`/nix/store/vs5bplf34cx0wk6py8myjc740dgqj2xm-source`, without changing the shared
environment. The earlier launch failure is retained in the v1 host log.
