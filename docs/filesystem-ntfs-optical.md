# Direct NTFS user namespace to optical capture

The separate `integration/optical/tests/ntfs_capture.rs` enabled gate sends a native NTFS image through read-only `RawDisk`, `NtfsVolume`, explicit `NtfsTreePolicy::UserNamespace`, and the deferred optical writer bridge. No host-tree extraction occurs during capture. Host extraction is used afterward solely as an independent optical validation oracle.

Complete NTFS capture is not established. Default Complete inventory rejects unsupported reserved system objects. The opt-in user profile retains exact excluded native root names, selectors and source/sequence IDs in the receipt and opaque root metadata. `RequireMetadata` rejects before staging; `ContentOnly` explicitly transforms metadata and excludes those declared reserved occurrences. It does not preserve NTFS ownership/security, raw parent references, native metadata streams, or complete volume state.

The native gate formats a fresh 64 MiB mkntfs image and writes 32 files of 131089 bytes with ntfscp. An allocated `$I30` B-tree supplies the namespace. Every file name and native record is compared against TSK `fls`; selected direct stream bytes are compared against `icat` and the independently generated host payload. ISO and UDF are then staged directly from TreeSource. Both are independently extracted with 7z and all 32 files checked byte-for-byte and by SHA-256. Native source and staged destination hashes remain unchanged through validation, and all resource leases refund after handles drop.

Native hard-link authoring is outside the tool fixture: independently authored NTFS index fixtures establish shared identities and deferred reads. This gate establishes content-only capture of the selected namespace on a clean NTFS3.1 fixture, not complete filesystem capture, journal replay, Windows servicing, or firmware boot.

```sh
nix-shell -p ntfs3g sleuthkit --run 'PARTMGR_NTFS_OPTICAL_EVIDENCE=/data/cache/partmgr-ntfs-optical-new cargo test --manifest-path integration/optical/Cargo.toml --locked --features native-writer --config '\''patch.crates-io.partmgr.path="/home/rick/projects-caddy/partmgr"'\'' --test ntfs_capture -- --ignored --nocapture'
```

The enabled gate requires the NTFS tools, Sleuth Kit, sha256sum, 7z/7zz, and a fresh explicit evidence directory. Missing prerequisites fail rather than skip. libmkiso resolves to the published registry version 0.1.4; only partmgr is patched to the checkout under test. Receipts retain commands, separate stdout/stderr, tool versions/binary hashes, reader/tree/bridge/test sources, test binary, source and destination hashes, exact exclusions and optical transformation reports.

The local passed receipt is `/data/cache/partmgr-ntfs-optical-native-20261008-frozen/receipt.txt`. Each format reports 32 entries, 32 unique files, 33 metadata objects, 132 discarded known fields, 132 uninspectable fields and 34 opaque fields. These counts describe intentional ContentOnly transformations and are not metadata-preservation claims.
