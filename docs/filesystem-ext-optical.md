# Native ext2 to staged optical content capture

The explicit native integration gate in
`integration/optical/tests/ext_capture.rs` demonstrates the plan's direct
filesystem-to-optical pipeline. It consumes an independently authored ext2
image through `RawDisk -> ExtVolume -> ExtTreeSource -> stage_iso/stage_udf`.
It never extracts an ext2 host tree for the optical writer to walk. The only
host payload supplied to debugfs is independently generated fixture input;
7z extraction happens after optical staging as an independent output oracle.

The `ext2-optical-content-only-v1` profile uses an 8 MiB classic ext2 image
created by `mke2fs -t ext2 -O none -I 128`. Native debugfs creates `nested`, writes
a 262,161-byte payload (larger than the writer's 64 KiB streaming buffer), and
adds root `alias.bin` as a hard link to `nested/payload.bin`, with link count two.
The source inode is explicitly set to mode `0100640`, uid 123, gid 456, and mtime
1000000000. Native `e2fsck -fn` must accept the fixture before and after capture.
The standard `lost+found` directory remains part of the captured namespace.

Common source inventory must identify both names as the same object, inspect
mode `0100640`, known UID/GID ownership and opaque native mtime:
this ext2 metadata decoder does not invent values it has not implemented.
`WritePolicy::RequireMetadata` must fail before creating a staged image or
retaining additional memory. `ContentOnly` is separately authorized and its
report must count known fields transformed and opaque native fields unpreserved.
Each output report covers five metadata inspections: root, `lost+found`,
`nested`, and both file namespace entries, with one unique file identity.

ISO selects Rock Ridge and Joliet, with explicit primary `FilenamePolicy::Mangle`
for names such as `lost+found`. Original names remain available in the selected
Rock Ridge/Joliet namespaces. The two file paths must share payload extents;
Rock Ridge records must retain link count two. ContentOnly deliberately
transforms the source permissions/ownership to default file mode `0100644`,
uid zero and gid zero. Those emitted fields are checked directly.

UDF must retain the two names' shared ICB identity. Its emitted native metadata
must have the writer defaults uid/gid `0xffffffff` and permissions `0x14a5`,
rather than implying preservation of ext2 ownership or POSIX mode. Deferred
source-backed UDF reads check the non-aligned final payload range. For both
formats, independent 7z extraction of both names must produce bytes and SHA256
identical to the independently generated payload. Both staged image hashes
must remain unchanged through read validation. Dropping each staged guard
removes its temporary image and restores the pre-staging shared memory charge.
After the source inventory drops, its 8 MiB shared pool must have zero charge.
The source ext2 image's SHA256 must remain unchanged throughout capture.

This test is marked ignored by default because it is an explicit external-tool
gate. Enabling it requires `mke2fs`, `debugfs`, `e2fsck`, `sha256sum`, and either
`7z` or `7zz`; missing tools fail the enabled gate. Run it deliberately:

```sh
PARTMGR_EXT_OPTICAL_EVIDENCE=/data/cache/partmgr-ext-optical \
  cargo test --manifest-path integration/optical/Cargo.toml \
  --features native-writer --test ext_capture -- --ignored --nocapture
```

Development-only owner overrides may be appended with `--config` before the
`--` separator, as documented in the optical reader integration. They are not
stored in package manifests or release lockfiles. Released dependency resolution
remains a separate gate.

With the evidence variable set, the harness retains its native ext2 fixture,
debugfs command file, expected payload, copied optical artifacts, native
extractions, and `ext2-optical-content-only-v1.txt`. The receipt includes exact
commands, exit statuses, full version output, source/package file and test
binary hashes, input/output SHA256 values, transformation reports and terminal
status. Copies of staged outputs retained for test evidence are not an API
publication operation; the actual staging guards still delete their own paths.

This proves the selected content-only capture pipeline and hard-link
relationships. It does not prove faithful ext2 metadata capture, complete ext
family support, all-filesystem preservation, source snapshot isolation,
cross-inode allocation ownership auditing, recovery or firmware boot correctness.

Verified registry-libmkiso receipt:
`/data/cache/partmgr-ext-optical-vdisk02-final-20261008/ext2-optical-content-only-v1.txt`.
The enabled native gate passes with e2fsprogs 1.47.4 and p7zip 17.05; both
independent optical extraction checks ran and matched both file SHA256 values.
The receipt retains native executable hashes, participating repository/package
source hashes, and the exact test executable hash. Targeted clippy with
`-D warnings` passes. Published libmkiso 0.1.4 was selected without an owner
checkout override. Only the unreleased partmgr API checkout still needs its
command-only development override.
