# Registry-backed ImageWriter session bridge

`fs_storage::ImageWriterSession::new` consumes an explicitly opened `virtdisk::ImageWriter`, checks
the actual handle's read/write/flush capabilities, and owns it privately through
`BoundedSession`. The caller supplies the fixed logical region. Management,
writer aliases and immutable ReadAt are absent from the session's public API.

Successful `write_all_at` becomes a full-length `Storage::write_at` result;
errors propagate without inventing a partial count. The session records sticky
uncertainty. Bounds/overflow fail before mutation. Zeroing uses bounded scratch
and flush remains explicit. Known logical/physical sector facts are retained;
caller facts fill unknown values and conflicting known facts reject. No atomic
sector-write property is inferred.

The writer retains its backend lock. Advisory locking cannot exclude arbitrary
external writers or mounted access. Parents must remain immutable. Container
consistency, filesystem ownership, partition layout and publication-directory
durability remain separate caller obligations and evidence gates.

Focused tests exercise real raw and Linux QCOW2 ImageWriter handles: retained
writer lock, crossing/overflow/zero rejection, read-after-write, explicit flush,
reopening and exact whole-logical-image comparison. Private fault wrappers retain
a real raw writer and inject an error after a partial real write, or at a flush
barrier. These establish bridge uncertainty/error behavior; they do not simulate
all container-internal failures or prove power-loss recovery. Generic short-write
and fault-session tests remain in the root crate.

```sh
cargo test --manifest-path integration/storage/Cargo.toml --locked \
  --config 'patch.crates-io.partmgr.path="/path/to/partmgr"'
```

The root crate now requires published crates.io virtdisk **0.2.0**. The adapter
lives in the root storage layer; `integration/storage::WriterSession` is a
compatibility re-export and standalone consumer test package. It stores no
sibling patches. Only partmgr's new unpublished filesystem APIs need the
command-only development override above. The resolved registry checksum is
`ed266f4c5cae3fba8b0470b42cfe43dd379c12ecfaab31a52f56456ce0fe4f8d`.

Root and consumer formatting, strict locked Clippy and ordinary tests pass.
The real-writer uncertainty fault test now runs in the root crate. The explicitly
enabled native consumer also passes qemu-img check and independent raw conversion
with exact whole-logical-image comparison and unchanged QCOW2 bytes. Its registry
receipt is
`/data/cache/partmgr-writer-bridge-registry-20261008/writer-bridge-mV5nUM/evidence.txt`.
Run it with `PARTMGR_STORAGE_EVIDENCE` set and `--test session -- --ignored`;
missing tools fail. Wider container, performance and filesystem recovery profiles
remain follow-up acceptance work.

The plain wasm32-unknown-unknown reader consumer currently fails because virtdisk
0.2.0 unconditionally pulls getrandom without a suitable target backend. A
flags-only unsupported-backend diagnostic compiles, but is not the release gate.
`../virtdisk/FILESYSTEM_V020_PORTABLE_FOLLOWUP_PLAN.md` records the narrow owner
refactoring request. Native registry availability is established; portable reader
compatibility remains open. No physical-device or container-wide crash guarantee
is inferred from these tests.
