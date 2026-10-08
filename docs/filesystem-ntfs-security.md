# Native NTFS security inspection

`fs_ntfs_security` inspects native Windows security descriptors and resolves NTFS
security IDs. It does not evaluate access, resolve account names, grant restore
permission, replay a journal, or acquire a Windows snapshot. The existing reader's
caller-established immutable-source contract still applies.

`NtfsSecurityDescriptor::parse` accepts self-relative revision-1 descriptor bytes
under explicit byte, total-ACE and structural-work limits. It retains a charged
copy of the complete original bytes, including uninterpreted fields and padding.
Owner/group SIDs expose exact bytes, a big-endian identifier authority and ordered
little-endian subauthorities. SACL and DACL each retain three distinct states:
absent, present with a null pointer, and present with an ACL (including an empty
ACL). Offsets whose PRESENT control bit is clear are preserved but not followed.
Descriptor control bits and the resource-manager control byte remain unchanged.

ACL iteration preserves ACE order, types and inheritance/audit flags. Supported
common, object, callback, label/resource/policy/trust/filter layouts expose checked
access masks and trustee SIDs. Object GUIDs retain their native bytes. Callback
and other application payloads remain opaque. Unknown ACE types, including layouts
not interpreted by this implementation, retain their complete header and body;
they are not removed or converted to POSIX permissions. Structural inspection is
not a claim that Windows will accept an ACL or that its access decisions are known.

`lookup_ntfs_security(volume, record, limits, resources)` checks a source- and
sequence-bound FILE record. It supports resident and initialized nonresident
per-record `$SECURITY_DESCRIPTOR` attributes, or resolves the extended
`STANDARD_INFORMATION` security ID through `$Secure`. Mixed authorities, split
unsupported streams and unavailable IDs fail explicitly. `NtfsResolvedSecurity`
has immutable getters for its bound FILE identity, descriptor and native origin.
Callers cannot relabel the returned descriptor as another record.

Shared lookup traverses actual `$SII` and `$SDH` INDEX_ROOT/INDEX_ALLOCATION trees.
It checks collation, boot-bound index geometry, INDX update-sequence fixups, VCN
alignment/ranges, bitmap allocation, child key bounds, ordering, repeated nodes,
terminal records and indexed header agreement. Limits bound nodes, entries, depth,
work and shared memory before retained index allocations. Allocated unreachable
index nodes fail. The selected `$SDS` descriptor must have matching primary and
256-KiB mirror bytes, indexed headers and the native rotate/add hash. That native
hash is a consistency check, not cryptographic authentication. Lookup validates
the selected descriptor; it does not establish complete ownership or semantic
validity of every other descriptor in the security database.

`lookup_ntfs_secure_id` independently inspects an explicitly selected database ID.
Its returned `$Secure` identity is distinct from file assignment; it cannot attach
that ID to a file whose stored ID differs. Deferred stream reads honor cancellation,
source-length checks, short reads and existing checked mappings. Sparse or
uninitialized security/index storage and unsupported split/attribute-list security
layouts remain explicit profile gates rather than zero-filled substitute metadata.

The volume-aware `fs_ntfs_metadata` wrapper retains base metadata and resolved
security under their original leases. Its consuming `into_metadata` operation
copies exact native descriptor and owner-SID bytes after reserving the additional
memory. Other unavailable classes remain explicit. These are native NTFS bytes,
not POSIX identity mappings. A parser and metadata capture API alone do not prove
end-to-end ACL restoration, cross-format preservation or Windows snapshot isolation.

## Evidence and remaining qualification

Independent byte fixtures cover null/empty/absent ACLs, unusual SIDs, aliased
owner/group SID locations, ordered unknown/object/callback ACEs, malformed offsets,
truncation, caps, cancellation and refunds. Separate hand-authored NTFS fixtures
exercise both security indexes, physical SDS mirrors, hash/header disagreements,
allocated INDX fixups, invalid VCNs, a child cycle, a free bitmap reference and
metadata-copy budget/cancellation refusal. No production encoder constructs those
fixture records.

The explicit native gate
`native_secure_ids_sds_sii_sdh_and_ntfs3g_raw_oracle` requires
`PARTMGR_NTFS_SECURITY_EVIDENCE`; enabled missing tools or failed commands fail the
test. Retained `/data/cache/partmgr-ntfs-security-native-v3/qualification.json`
binds 13 archived compiled sources, the fixed executable and 75 artifacts. The
mkntfs/ntfscp volume's root nonresident descriptor (4140 bytes), file resident
descriptor (80 bytes) and native indexed security ID 256 match independent
`ntfscat` descriptor/SDS bytes. Both SDS copies match. The combined metadata
conversion checks exact descriptor and owner bytes and lease refunds. This is
Linux native-tool evidence. The separately frozen isolated expanded gate at
`/data/cache/partmgr-ntfs-security-allocated-native-v2/qualification.json` retains
13 compiled sources and 3159 artifact hashes. Published `ntfssecaudit` writes all
512 permission-mode combinations to one disposable file; a Linux user namespace
maps the caller UID to namespace root without host root privileges. This forces
11 `$SII` and 10 `$SDH` native INDX nodes and 514 indexed descriptors. Every complete
descriptor matches independently extracted SDS bytes and its mirror, and the
native security database audit reports no errors. The fixture producer uses POSIX
mode inputs to native tools; the reader and metadata capture preserve resulting
native descriptors rather than converting them back to POSIX permissions. Windows
ACL/VSS/restore oracles remain separate requirements. The earlier native-v1
unsupported nonresident-descriptor failure is retained as historical evidence.

## Primary references

Descriptor, SID, ACL and ACE framing follow Microsoft
[MS-DTYP SECURITY_DESCRIPTOR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d),
[ACL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428)
and [object ACE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe).
The pinned Linux v6.12 implementation supplies concrete NTFS native
[index/header definitions](https://github.com/torvalds/linux/blob/v6.12/fs/ntfs3/ntfs.h)
and [$Secure/hash/mirror implementation](https://github.com/torvalds/linux/blob/v6.12/fs/ntfs3/fsntfs.c).
These references support structural interpretation, not a Windows-native acceptance
claim for framework output.
