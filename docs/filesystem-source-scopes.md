# Source scope allocation

`ObjectId.source` is an opaque process-local source/session identity. It is not a
filesystem type, authentication proof, persisted volume ID or snapshot guarantee.
Its native key and generation are interpreted only by the owning source. Cached
metadata, directory continuation tokens and deferred handles must reject another
source or a changed generation before using mappings.

The current development engines reserve distinct high-word domains and allocate
the low word through checked counters; exhaustion fails instead of wrapping.
These values are implementation reservations, not a public encoding contract.

| Built-in owner | Reserved high word |
| --- | --- |
| Immutable FAT reader | 0 |
| Immutable classic ext2 reader | 2 |
| Immutable exFAT reader | 3 |
| Immutable NTFS reader | 4 |
| Exclusive FAT editor | 5 |
| Exclusive exFAT editor | 8 |
| Immutable XFS reader | 9 |
| Immutable JFFS2 reader | 10 |
| Immutable HFS+/HFSX reader | 11 |
| Exclusive classic ext2 editor under development | 12 |
| Exclusive JFFS2 editor under development | 13 |
| Immutable classic HFS reader under development | 14 |
| Immutable JFS reader | 15 |
| Immutable APFS container/volume reader | 16 |
| Owned APFS COW session under development | 17 |
| Owned modern ext journal session under development | 18 |

Borrowed mutable decoders receive the existing editor scope and allocate no
independent immutable identity. A successful transaction or recovery invalidates
old generation handles; it does not transfer them to a reopened source.
Uncertain transactions gate access until the owner completes required recovery.

Adapters or caller-created TreeSource implementations assigning their own scopes
must ensure uniqueness across the actual sources they combine. In particular,
the optical read adapters currently take an explicitly supplied scope; they must
not reuse a live built-in scope or another optical source. Preserving a source
identity while translating an existing tree is different from opening a new
independent source and must retain that original ownership relationship.

The XFS facade regression opens a FAT editor and XFS reader together and checks
their distinct domains independently of counter values. FAT/exFAT tests likewise
check independent reader scopes. Scope equality or a read-only OS handle never
establishes immunity to external mutation; callers must provide the advertised
storage stability throughout deferred reads.

The JFFS2 editor and classic HFS reader now allocate domains 13 and 14. Their
operation profiles and validation status remain independent of these process-local
identity reservations. A scope is not permission to program or erase flash.

The JFS reader allocates domain 15. Its initial Linux profile now has a reader,
allocation/reference audit and TreeSource; the domain itself remains only a
process-local identity distinction and does not establish profile support.

The APFS immutable container/volume reader allocates domain 16. Its bounded
checkpoint, volume and allocation-audit evidence is recorded separately in the
support matrix; the domain remains only a process-local identity distinction.

Domains17 and18 are reserved for the developing owned APFS COW session and
owned modern ext journal session respectively. These reservations establish no
public writable API or acceptance claim. Their handles must use new process-local
counters and independent generations, while immutable APFS16/ext2 keep existing
identities. Source domains distinguish authorities; they do not authenticate
bytes or prove durable publication.

Domain19 is reserved for the developing owned JFS native journal session. This
reservation establishes no writable capability or native recovery acceptance.
Independent checked process-local counters/generations must bind handles to
that exclusive owner; immutable JFS15 retains its existing source identity.
