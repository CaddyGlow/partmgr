# Native external-undo consumer gate

`tests/fs_undo_native.rs` exercises the common undo protocol against real locked regular files. It supplies reviewed existing-file payload patches; it is not a public FAT editor and does not establish creation/deletion, allocation updates, FAT dirty-state ordering or metadata editing correctness.

The test independently creates a 16 MiB FAT16 image using `mkfs.fat --invariant -F 16 -s 1` and inserts a 20,000-byte `PAYLOAD.BIN` plus an unrelated `OTHER.BIN` using `mcopy`. It embeds the volume behind an 8192-byte prefix and ahead of a 4096-byte suffix. A complete FAT ownership audit and checked reader establish the file's allocation and payload; bounded physical patches are derived from validated file extents for logical ranges 123..400 and 4000..4500. Every immutable source, directory and deferred file handle is released before acquiring an exclusive `FileStorage` lock through `BoundedSession`.

The caller checks a SHA-256 binding covering the original volume and framing and supplies explicit generation/transaction values. Each transaction uses a separately created, pre-sized external journal file, opened and locked independently from its target. The protocol validates patches and journal binding; this fixture's caller stabilizes the files and chooses distinct target/journal objects.

Three actual file-backed scenarios run:

- Commit the reviewed payload replacement and reopen it.
- Persist half of a target write with a real delegated flush, return a modeled I/O error, drop both editing handles, and reopen them to undo.
- Repeat the target failure, then inject a half-write/error during rollback, reopen and retry rollback twice to verify restartability and terminal idempotence.

Each result is reopened through the checked FAT reader and ownership audit. Independent `fsck.fat -n` accepts the filesystem; `mcopy` extracts both files and their exact bytes match the expected outcome. A complete framed-image byte comparison checks all metadata, unrelated payload, unused space and prefix/suffix bytes, rather than checking only selected payload hashes. The original framed source remains byte-identical.

These checks use actual writes and flush calls with modeled errors. They do not simulate physical power loss, device cache behavior or controller failure. The common protocol's separate modeled durable-state fault matrix remains necessary; these native tests establish one real consumer path for existing payload ranges.

## Running and receipts

The gate is explicitly ignored during portable tests. Enabling it requires an evidence directory; missing tools fail the test:

```sh
PARTMGR_UNDO_NATIVE_EVIDENCE=/data/cache/undo-native-evidence \
  cargo test --test fs_undo_native --all-features --locked -- --ignored
```

Tool overrides are `PARTMGR_UNDO_MKFS`, `PARTMGR_UNDO_FSCK` and `PARTMGR_UNDO_MCOPY`. Defaults select the installed `/run/current-system/sw/bin` executables. `sha256sum` must be available. The receipt retains exact argv, version output, executable hashes, source/protocol/test-binary hashes, original and resulting artifacts, extracted payload hashes, binding values and physical patch offsets/lengths/old-new hashes. Artifact directories include all target images and external journals.

The 2026-10-07 run passed with dosfstools 4.2 and GNU mtools 4.0.49. Its receipt is `/data/cache/partmgr-undo-native-vdisk02-20261008/fat16-external-undo-existing-payload-v1.txt`. Focused clippy passed; the ignored test remains opt-in for portable environments.
