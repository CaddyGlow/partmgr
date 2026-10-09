# BitLocker inspection, reading, and ciphertext transactions

Enable the optional `bitlocker` Cargo feature to inspect and read encrypted
volumes through `partmgr::bitlocker`. The engine composes the existing `ReadAt`
interface with portable AES, CCM, SHA-256, and XTS implementations. It works with
`std` or `no_std` plus `alloc` and introduces no TPM or native-library dependency.

```toml
partmgr = { version = "0.1.1", features = ["bitlocker"] }
# For portable consumers:
# partmgr = { version = "0.1.1", default-features = false, features = ["bitlocker"] }
```

This implementation is experimental. Windows build 26200 full-volume XTS-AES-128
and XTS-AES-256 fixtures with 512-byte sectors pass recovery unlock, wrong-password
rejection, and native file-hash comparison. The XTS128 gate also compares native
boot and reserved-region samples. A host ciphertext replacement on an isolated
XTS128 copy passed Windows recovery unlock, modified-file SHA-256 comparison,
`chkdsk /scan`, and clean detach. See the exact artifacts and limits in
[the evidence record](../integration/bitlocker/EVIDENCE.md). Broader capture,
swtpm, creation, and firmware qualification remain separate gates in
[the implementation plan](bitlocker-plan.md).

## Implemented operations

| Operation or profile | Behavior |
| --- | --- |
| Signature probe | Returns a candidate envelope without claiming valid metadata or supported unlocking. |
| Metadata inspection | Bounded version-2 blocks and version-1 datasets, redundant-copy diagnostics, structural checks, and CRC verification. |
| Metadata selection | Requires byte agreement among usable copies, or an explicit copy index. Corrupt copies remain visible in diagnostics. |
| Recovery password | Selects a protector by native identifier, derives its key, authenticates VMK unwrap, then authenticates FVEK unwrap. |
| Clear-key protector | Requires explicit selection, including for suspended protection; encryption state is checked independently. |
| Supplied VMK | Authenticates the wrapped FVEK using the caller's 32-byte VMK. |
| Supplied FVEK | `FullVolumeKey` binds method and length; `unlock_with_fvek` rejects a cipher mismatch and records `KeyEvidence::CallerSupplied`. The slice API remains available. |
| XTS-AES reading | Methods `0x8004` and `0x8005`, with 512 or 4096-byte logical sectors. |
| Logical mapping | Relocated boot sectors use their physical volume-relative tweak; reserved metadata and backup regions read as zeros. |
| Native data-disk provisioning | The Windows adapter creates a fresh GPT/MSR/NTFS fixed VHD with full XTS encryption and a generated recovery protector; the corrected single-MSR fixture passes the portable read gate. |
| Filesystem integration | Pass the decrypted reader into `fs_image::probe`, `ReadImage::open`, or `NtfsVolume::open`. |

Reading requires the full-volume identifier, current and target state both set
to completed encryption, bounded aligned regions, a usable boot-sector count,
and either no area descriptor or the basic 16-byte area descriptor matching the
header, or the strictly checked 92-byte Windows build 26200 full-volume
extension. The latter additionally reserves its declared metadata area; other
extensions, conversion logs, flags, and build profiles remain unsupported.
Inner filesystem readers retain their own geometry and feature limits; the current NTFS reader requires 512-byte
sectors even though the BitLocker reader also supports 4096-byte sectors.

TPM protectors can be enumerated, but native TPM/swtpm unlocking is unavailable.
A VMK acquired externally can be supplied explicitly. Used-space-only encryption,
conversion in progress, legacy CBC/diffuser methods, removable discovery layouts,
password/BEK protectors, and hardware encryption are unsupported.
The separate `bitlocker-write` feature supports explicit logical replacements for
the same full-volume XTS profile; conversion, resizing, protector changes, and
BitLocker metadata mutation remain unsupported.

## Explicit unlocking

The source must be a stable bounded volume. Select it with
`PartitionTable::select`, construct a `DiskView`, or supply a retained standalone
volume reader. Do not pass the entire partitioned disk as though it were a volume.

```rust,ignore
use std::sync::Arc;
use partmgr::{
    bitlocker::{BitLockerVolume, Limits, MetadataSelection, RecoveryPassword},
    fs_core::Resources,
    io::ReadAt,
};

fn open_volume(
    source: Arc<dyn ReadAt>,
    protector_id: [u8; 16],
    recovery_password: &str,
    resources: &Resources,
) -> partmgr::bitlocker::Result<Arc<dyn ReadAt>> {
    let volume = BitLockerVolume::inspect(
        source,
        MetadataSelection::RequireAgreement,
        Limits::default(),
        resources,
    )?;
    let password = RecoveryPassword::parse(recovery_password)?;
    let reader = volume.unlock_recovery(protector_id, &password)?;
    Ok(Arc::new(reader))
}
```

Use `volume.protectors()` to inspect identifiers and protection types before
selecting one. Native identifiers are raw Windows GUID bytes, including Windows
field byte ordering; display-string conversion is a caller responsibility.
`volume.read_support()` reports the validated mapping or a machine-readable
profile limitation before credential work. Malformed mapping remains an error.
The library does not choose a credential, fall back to a clear key, or try other
protectors when an explicit unlock fails.

The unlocked reader retains the source, resource policy, and AES schedules after
the inspected volume is dropped. It has no write capability. Its length is the
validated metadata-declared encrypted volume length. Arbitrary unaligned reads,
concurrent reads, and empty reads at EOF follow the upstream positional contract.
Invalid ranges return `UnexpectedEof`. Failed reads can leave output partly
modified; discard the output when an error is returned.

## Resource and integrity contracts

`Limits` bounds metadata bytes, entry counts, nesting, key-derivation iterations,
and cumulative physical read bytes. Inspection and every reader share the last
counter; partial requests charge complete underlying sectors, while synthesized
reserved-region zeros require no backend reads. Failed backend attempts consume
their charge. `Resources` supplies retained memory accounting and cooperative
cancellation. Per-read scratch is bounded and zeroed on drop; there is no
plaintext cache or whole-volume extraction.

Memory accounting includes retained metadata, reader cipher schedules, and scratch.
Internal secret wrappers erase their owned buffers on drop, and the AES dependency
enables key-schedule zeroing. Original caller strings/key slices remain the caller's
responsibility. This does not establish protection against swap, crash dumps, or
every compiler-generated intermediate of the SHA-256 implementation.

Validation-header versions 1 and 2 use CRC checks for accidental metadata
corruption. The optional encrypted metadata-validation payload is not validated. Authenticated key unwrap
establishes the integrity of those key records, not of plaintext data sectors or
the entire metadata selection. XTS sectors remain unauthenticated. Validate the
inner filesystem independently, and inspect `key_evidence()` when using supplied
keys. Successful unlocking is not a filesystem allocation audit.

Keep every source and backing parent unchanged throughout inspection and deferred
reads. The reader checks backing length and provider identity before and after backend reads; this does
not detect arbitrary same-length mutation or create snapshot isolation. Forwarded
context describes the retained container. Each unlocked reader receives a distinct
process-local source identity and retains the ciphertext source as an ancestor.
`provenance()` reports the encrypted source identity, selected profile, mapping,
and key evidence without credentials. Independent unlocks receive different
tokens, even for the same key; tokens are not persistent content hashes. Capture
receipts still need acquisition/snapshot evidence and filesystem validation.
Sparse ciphertext holes are not advertised as plaintext holes.

## Validation and references

`tests/bitlocker.rs` exercises independently generated recovery, AES-CCM, and XTS
vectors, malformed metadata, copy disagreement, source changes, resource limits,
concurrency, and the existing NTFS reader. Regenerate the checked-in vectors with
`python3 tests/fixtures/generate_bitlocker_vectors.py` using `cryptography 48.0.0`,
then format the generated Rust file. Test execution needs neither Python nor a VM.

```sh
cargo test --features bitlocker --locked --test bitlocker
cargo check --no-default-features --features bitlocker --locked
```

The format profile follows published on-disk analysis, with strict refusals for
unimplemented cases. References are the
[libbde format analysis](https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc),
[RustCrypto CCM API](https://docs.rs/ccm/0.5.0/ccm/), and
[XTS mode API](https://docs.rs/xts-mode/0.5.1/xts_mode/).

## Envelope discovery

`volume_probe::probe` is available even without the BitLocker feature. It returns
`Candidate::BitLocker`, `Candidate::Plaintext` (inner filesystem candidates), or
`Candidate::Unknown`. Encryption signatures take precedence over filesystem
signatures; discovery never attempts unlocking or silently falls back to NTFS.

## Recoverable encrypted replacements

Enable `bitlocker-write` and use `bitlocker_write::BitLockerSession<S, J>` with
an exclusively owned bounded `Storage` target and a disjoint durable journal.
`SessionOptions` supplies metadata selection, resource limits, and the caller's
verified volume identity and acquisition generation. Open with an explicit
recovery, clear-key, VMK, or diagnostic FVEK credential.

`plan_replace` validates the entire logical range, rejects synthesized metadata
and backup regions, and maps logical boot bytes to their relocated sectors.
Partial sectors are decrypted in zeroed scratch, changed, and reencrypted using
their physical volume-relative XTS tweak. The retained plan contains only old and
new ciphertext. Review its required journal size and retain its `binding()` with
the external acquisition record before committing.

`commit` rechecks metadata and geometry, then uses `fs_undo` to persist undo
ciphertext before target writes. Plans are bound to their session and revision;
a successful commit invalidates earlier plans. Any undo failure permanently
fences the session. Use `into_parts`, call `recover_ciphertext` with the retained
binding, and acquire a newly inspected session. Recovery needs no decryption key.
Failed `open_*` calls return `OpenFailure` containing the error and both owned
stores, so a rejected acquisition cannot discard an in-memory recovery journal.
An invalid or torn journal authorization header is refused; it is not permission
to overwrite the target or erase evidence. Caller-provided stores must enforce
exclusivity and disjointness throughout this sequence.

The session deliberately does not expose a decrypted `Storage` adapter. General
filesystem editor composition, broader native write qualification, encryption
conversion, portable volume creation, and TPM unlocking remain separate plan
milestones. The recorded Windows write gate covers one in-place file-data
replacement; it does not qualify arbitrary filesystem metadata edits.
Host failure injection establishes the modeled ciphertext undo protocol only.

## Native integration gate

`integration/bitlocker` contains Windows fixture provisioning and deployment
adapters. The ignored `tests/bitlocker_native.rs` gate unlocks a quiescent native
fixture, rejects a wrong recovery password, and compares the named NTFS file with
a Windows SHA-256 oracle. See the integration guide for fixture inputs and actual
recorded results; an ignored test is not a passing interoperability result.
