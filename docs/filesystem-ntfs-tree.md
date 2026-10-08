# NTFS native directory indexes and TreeSource

`NtfsVolume::directory` enumerates the actual named `$I30` INDEX_ROOT and, when present, INDEX_ALLOCATION plus its resident `$BITMAP`. It does not scan MFT FILE_NAME attributes to invent a directory. The initial NTFS3.1 clean-volume reader profile still applies; journal replay remains unsupported. The separate [allocation/reference audit](filesystem-ntfs-audit.md) provides complete supported base-record ownership evidence; tree inventory alone does not run it.

Root and INDX headers, aligned entry/key bounds, terminal entries, internal-node child flags, USA array bounds/trailers, stored child VCN, allocation-map ranges and bitmap bits are checked. Index blocks smaller than clusters use sector VCN units; other indexes use cluster units. Allocated unreachable blocks, repeated child blocks, cycles and inconsistent references fail. The initial bitmap profile is resident; nonresident bitmaps, split attributes and other index names/collations fail explicitly.

Traversal visits children and separator entries in B-tree order and uses the native 128 KiB `$UpCase` table for filename collation. Case-fold collisions or unordered entries fail this strict profile; support for distinct case-sensitive POSIX colliding names is not claimed. Internal collation-table reads select the unnamed `$UpCase` stream even when its separate native `$Info` metadata exists; public file opening continues to reject alternate DATA streams. Each index occurrence must match an allocated target FILE sequence, native FILE_NAME selector/name and parent record/sequence. Directory kind is checked against the target FILE flag. Exact UTF-16 units, including unpaired surrogates, remain unchanged. The root dot self-entry is checked as a native reserved occurrence.

`NtfsDirectoryLimits { blocks, entries, depth }` bounds allocation blocks, all native index occurrences, and B-tree depth. Shared memory leases cover output names, maps, traversal tasks, bitmap, index scratch and collation bytes before allocation; output accounting remains live until the directory drops. Cancellation is checked throughout traversal. This is structural validation of an untrusted image, not cryptographic authentication or a whole-volume consistency claim.

`NtfsTreeSource::inventory` defaults to `NtfsTreePolicy::Complete`. Reserved root system objects cannot yet be captured faithfully, so complete inventory fails explicitly rather than dropping them. `inventory_with_policy(..., NtfsTreePolicy::UserNamespace, ...)` is an explicit caller opt-in: only validated root occurrences targeting reserved records 0..11 are excluded, including the root dot entry and `$Extend` metadata directory. Reserved references elsewhere or other reserved record classes fail. `excluded_entries()` returns the exact native leaves, namespace selectors and source/sequence identities. Root metadata includes `ntfs.capture.excluded-root-metadata` as an opaque packed occurrence report, forcing preservation preflight to account for this omission. This policy captures a selected user namespace, not every volume object or system stream.

Inventory bounds count the root and **every** index occurrence, including exclusions and hard-link/DOS aliases. Directory depth is checked before queuing descendants. Repeated directory identities fail as cycles/aliases. File aliases retain the same native identity and deferred unnamed DATA stream. Tree metadata additionally retains FILE_NAME parent references/selectors/units in an opaque `ntfs.FILE_NAME.occurrences` attribute; those references cannot be transplanted without a relocation policy. User alternate streams, reparse/offline/compressed/encrypted files and attribute-list layouts remain explicit errors. Directory DATA streams and unsupported EA/property/logged-utility metadata also fail the tree profile. Ownership and security remain uninspectable under the initial reader profile.

Directory pages carry live reservations and source/sequence-scoped continuations. Metadata, stream lists and deferred file maps share the caller pool. Handles own the stable source and survive dropping inventory. Revalidation checks record sequence, kind and file length; generic sources cannot detect same-length changes, so the caller must hold source stability throughout capture and repeated reads. No host-tree extraction or full payload construction is part of inventory.

`with_security_capture(NtfsSecureLimits, &Resources)` explicitly enables native
security preservation for this tree profile. It preflights every inventoried
object through volume-bound security lookup before enabling the mode. Subsequent
metadata reads retain exact self-relative descriptor and owner SID bytes, with
shared budget accounting and source/record identity validation. Unsupported
security or cancellation fails explicitly. The default record-only path still
reports security and ownership as uninspectable. Namespace exclusions remain;
this option does not establish complete-volume capture or ACL restore/edit support.

Seven ordinary tree tests include exact root/file descriptors, hardlink identity,
cancellation and lease refunds. The separately enabled
`native_security_tree_capture_exact_descriptor_oracle` compares actual root and
file descriptors with ntfscat and independently reads native owner SID offsets.
The frozen receipt is
`/data/cache/partmgr-ntfs-acl-tree-native-v4/qualification.json`; its 26 artifact
hashes and imported tree source/test files were independently verified. Native
Windows snapshot capture and restore remain separate acceptance gates.

Primary layout/traversal references are pinned Linux v6.17 NTFS3 [structures](https://github.com/torvalds/linux/blob/v6.17/fs/ntfs3/ntfs.h) and [index implementation](https://github.com/torvalds/linux/blob/v6.17/fs/ntfs3/index.c). Independent byte fixtures exercise resident and allocated indexes, hard-link occurrences, bounds, parent/sequence disagreement, malformed INDX fixups/VCNs, work limits, paging, child cycles, collation collisions, special-directory streams, I/O failures and lease refunds.

```sh
cargo test --locked --test fs_ntfs --test fs_ntfs_tree
nix-shell -p ntfs3g sleuthkit --run 'PARTMGR_NTFS_TREE_EVIDENCE=/data/cache/partmgr-ntfs-tree-new cargo test --locked --test fs_ntfs_tree native_large_directory -- --ignored --nocapture'
```

The explicitly enabled native gate fails if tools or evidence configuration are missing. It creates a fresh 64 MiB mkntfs image and 96 native ntfscp files, requiring an allocated B-tree; compares every user name/native record against independent TSK `fls`, selected deferred bytes against `icat`, and verifies the image hash remains unchanged. It checks default-complete rejection and explicit user-policy exclusion metadata. Commands, outputs, versions and source/tool/test-binary hashes are retained. Native hard-link authoring is not claimed by this tool fixture; independently authored hard-link fixtures cover identity semantics.

The passed large-directory receipt is `/data/cache/partmgr-ntfs-tree-native-20261008-frozen/receipt.txt`. Direct content-only optical capture is covered by [the separate native gate](filesystem-ntfs-optical.md).
