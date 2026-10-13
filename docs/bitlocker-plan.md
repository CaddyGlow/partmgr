# BitLocker implementation plan

Add portable BitLocker inspection and read-only unlocking to `partmgr`, with an
optional TPM 2.0 provider that can communicate with swtpm. Place decryption
between the bounded partition reader and the existing filesystem readers, so
NTFS inspection, file access, and capture can consume the same decrypted view.

The milestones below define the intended implementation and qualification. The
first release should support a precisely qualified modern software-encrypted
profile; additional formats and protectors advance through separate gates. This
work does not change the existing NTFS priority in `FILESYSTEM_PLAN.md`.

## Implementation checkpoint

The optional `bitlocker` feature now provides experimental portable version-2
metadata inspection, explicit redundant-copy selection, numerical recovery and
clear-key unlocking, supplied VMK/FVEK paths, and XTS-AES decrypted positional
reads. The reader handles relocated boot sectors and reserved metadata regions
and feeds the existing filesystem probe and NTFS reader. These operations have
independent crypto vectors and synthetic integration tests. Windows build 26200
full-volume XTS128/256 recovery/file-hash gates now pass with 512-byte sectors;
see [native evidence](../integration/bitlocker/EVIDENCE.md). Broader capture and
firmware qualification remain separate gates.

The implementation modules are `bitlocker.rs`, `bitlocker_disk.rs`,
`bitlocker_crypto.rs`, `bitlocker_write.rs`, and `volume_probe.rs`. The immutable
reader remains in `bitlocker.rs`; envelope discovery is feature independent.
The `bitlocker-write` feature now adds owned ciphertext replacement sessions and
external undo recovery with host interruption tests. An isolated XTS128
file-data replacement passed native Windows hash and consistency checks. Envelope discovery and
distinct decrypted-view provenance are also implemented. Windows provisioning
adapters and an opt-in native recovery/file-hash gate live in
`integration/bitlocker` and `tests/bitlocker_native.rs`. The corrected native
data-disk generator produced a single-MSR/GPT/NTFS fixed VHD that passed the
portable recovery/file-hash gate. Native Windows also boot-unlocked the dedicated
TPM-protected used-space-only system fixture; this is not host TPM-provider
evidence or qualification of the offline WinPE deployment adapter.
One strict Windows 26200 full-volume extended descriptor profile is implemented.
Experimental TPM/swtpm providers now live behind `bitlocker-tpm`, including strict
version-5 protector decoding, authenticated policy-session responses, bounded
Unix command transport, and isolated persistent-state import. Real synthetic
swtpm gates pass the complete VMK/FVEK authentication chain. A Windows-created
protector also passes native FVEK authentication after explicit measured-event
replay into an isolated matching TPM copy. This does not qualify live boot-time
handoff. See [provider evidence](bitlocker-tpm.md).
Further mapping descriptors, used-space-only encryption,
additional protectors, broader native write qualification, and portable
new-volume authoring remain future milestones. See
[the support guide](bitlocker.md) for the exact implemented profile and API.

## Expanded requested scope

Support both an encrypted data disk and a bootable Windows system disk containing
an EFI System Partition and Windows recovery partition. Add recoverable encrypted
writes, new-volume authoring, full-disk assembly, and unlock providers for a live
swtpm endpoint and an explicitly imported matching swtpm state. Treat UEFI variable
stores as boot-environment inputs rather than a volume-key credential.

These are required development targets, not capabilities of the current reader.
Keep the existing read feature usable while advancing each target through its
own native and interruption gates.

## Architecture and repository boundaries

The current insertion points are:

| Existing component | BitLocker integration |
| --- | --- |
| `src/io.rs` | Use the re-exported `virtdisk` positional I/O contracts without defining another reader trait. |
| `src/partition.rs` | Feed the bounded `DiskView` returned by `PartitionTable::select` into volume inspection. |
| `src/fs_image.rs` | Probe and open the inner filesystem after explicit unlocking. |
| `src/fs_ntfs.rs` | Supply the decrypted `Arc<dyn ReadAt>` to `NtfsVolume::open`. |
| `src/fs_core.rs` | Reuse resource budgets, cancellation, and source stability concepts. |
| `src/fs_copy.rs` and `src/fs_pipeline.rs` | Carry the unlocked source through existing file workflows and preserve capture provenance. |
| `src/fs_storage.rs` and `src/payload.rs` | Keep mutable storage, resize, and raw payload operations distinct from decrypted reading. |

The intended data path is:

```text
virtdisk image or caller-provided ReadAt
    -> partition DiskView, or an explicitly supplied whole-volume view
    -> volume probe
    -> BitLocker metadata inspection
    -> selected protector and explicit credential/provider
    -> validated unlocked volume
    -> decrypted ReadAt
    -> filesystem probe and ReadImage/NtfsVolume
    -> file inspection, copy, or capture
```

Implement the portable format engine in this crate first. Keep its internal
boundaries suitable for later extraction, but do not require a new sibling crate
or local path dependency. Published dependencies must resolve from crates.io.
Disk container decoding stays in `virtdisk`; BitLocker metadata and protector
interpretation stay in the volume layer.

## Scope and support profiles

Represent support as a combination of metadata version, encryption method,
conversion state, protector type, sector geometry, and operation. Detecting a
signature must not imply that unlocking or reading is supported.

| Capability | Planned order and qualification |
| --- | --- |
| Signature and bounded metadata inspection | First milestone; report recognized unsupported profiles explicitly. |
| Caller-provided full volume encryption key | Early diagnostic path to qualify sector reading independently of protector handling. |
| Numerical recovery password | First ordinary credential path, including format validation and authenticated key unwrapping. |
| Modern XTS-AES 128 and 256 software encryption | Initial data-plane targets, each with independent fixtures. |
| Fully encrypted and completed used-space-only volumes | Separate fixtures and support decisions; conversion state must be understood. |
| TPM 2.0 with swtpm | Required project milestone after portable unlocking works; qualify actual Windows-created protectors. |
| TPM with PIN or startup key | Separate profiles after TPM-only success; never silently drop additional factors. |
| External startup/recovery key files and password protectors | Follow-up profiles with independent parsing and derivation tests. |
| Suspended protection and clear-key protectors | Explicit selection and reporting; suspended protection does not imply plaintext volume data. |
| Older CBC/diffuser profiles and TPM 1.2 | Detect where possible, initially return unsupported. |
| Conversion in progress or paused mid-conversion | Initially refuse decrypted reads unless the exact mixed-layout profile is implemented and qualified. |
| Hardware encryption, network unlock, certificate protectors, removable-media legacy layouts | Separate research and qualification; no generic support claim. |
| Encrypted writes, enabling/disabling encryption, protector mutation, resize | Deferred to a separate durable mutation design. |

BitLocker operates at the volume layer. Successful unlock does not establish
that the contained filesystem is NTFS, clean, or supported. Filesystem EFS
decryption also remains an independent capability.

## Proposed module layout

| File | Responsibility |
| --- | --- |
| `src/bitlocker.rs` | Public inspection, profile, limits, credential, and unlocked-volume API. |
| `src/bitlocker_disk.rs` | Bounded on-disk header, metadata block, and entry decoding. |
| `src/bitlocker_crypto.rs` | Reviewed crypto primitives, derivation, authenticated key unwrap, and sector transforms. |
| `src/bitlocker_read.rs` | Logical volume mapping and `ReadAt` implementation. |
| `src/bitlocker_tpm.rs` | Portable TPM protector interpretation and provider contract. |
| `src/bitlocker_tpm_host.rs` | Optional host TPM stack and swtpm transport integration. |
| `src/volume_probe.rs` | Volume-envelope detection before filesystem dispatch. |
| `tests/bitlocker_*.rs` | Public API, corruption, resource, crypto, and reader tests. |
| `tests/fixtures/bitlocker_*.rs` | Small deterministic synthetic fixtures with documented provenance. |
| `integration/bitlocker/` | Windows, QEMU/OVMF, swtpm, and independent-tool qualification harness. |
| `docs/bitlocker.md` | Qualified support matrix and user-facing examples after implementation. |

Use submodules rather than splitting every helper into a new file. Keep TPM
transport dependencies out of the portable build. A likely feature split is
`bitlocker` for the portable engine and `bitlocker-tpm` implying `bitlocker` and
`std` for host integration. Confirm dependency portability and feature unification
before committing to names or exposing public types.

## Public API and state transitions

Use distinct inspected and unlocked types. Inspection is credential-free and
returns volume identity, metadata-copy diagnostics, conversion state, cipher
profile, protector identifiers/types, and supported operations. It must not
expose secret material through ordinary reports or `Debug`.

The conceptual interface should provide these operations:

1. `inspect(source, limits, resources)` retains a bounded stable source and
   returns an inspected BitLocker volume.
2. `protectors()` exposes non-secret summaries and stable identifiers.
3. `unlock(protector_id, credential_or_provider, resources)` validates one
   explicit selection and returns an unlocked volume or a typed failure.
4. `reader()` supplies a shared immutable decrypted view implementing the exact
   existing `ReadAt` contract.
5. A separate explicit diagnostic constructor accepts a typed supplied FVEK and
   cipher profile. It must report that key correctness was not established by an
   authenticated protector unwrap; a plausible filesystem signature is not an
   authentication proof.

Use secret-owning wrappers without ordinary `Clone`, serialization, or revealing
`Debug` implementations. Prefer borrowing credentials for the unlock operation
and retaining only what subsequent sector reads need. Destroy intermediate
secrets on every success, failure, and cancellation path using reviewed zeroing
support; document that this does not guarantee removal from swap or crash dumps.

Keep the TPM provider concerned with satisfying a selected protector. The
portable layer owns BitLocker metadata interpretation and subsequent key
unwrapping. Determine the exact TPM-returned secret and its relationship to the
volume master key from the implemented Windows profile; do not assume every
unseal response is directly an FVEK or VMK.

Provide machine-readable failures for malformed metadata, unsupported profile,
ambiguous metadata selection, credential rejection, missing additional factor,
TPM policy failure, TPM lockout, transport failure, changed source, cancellation,
resource exhaustion, and backend I/O. Preserve underlying causes through the
existing portable error boundary without embedding credentials or decrypted keys.

## Metadata inspection and selection

Implement strict bounds checks before following any offset, count, nested entry,
or variable-length field. Bound metadata copies, entry nesting, aggregate decoded
bytes, protector counts, and total work. Use checked arithmetic and fallible
allocation; metadata cannot dictate unlimited allocation or expensive derivation.

Locate and inspect redundant metadata blocks according to the supported format
version. Validate lengths, identity, sequence/state relationships, and available
integrity fields. Record each copy's validity and rejection reason. Establish
selection rules from format evidence and Windows fixtures; do not invent a
generic newest-timestamp or majority-vote rule. Conflicting usable copies should
produce an ambiguity result unless the profile provides a verified selection rule.

Retain bounded opaque records for unknown entries when safe, but refuse unlock
when an unknown required field affects policy, keys, conversion, or mapping.
Optional metadata recovery must be an explicit selection operation and must not
silently repair or write the volume.

Validate logical sector size and volume length against the selected profile and
caller-supplied geometry. Do not infer a usable plaintext length merely from the
backing partition length. Keep partition-relative offsets and logical decrypted
volume offsets distinct throughout decoding.

## Portable unlocking and sector reads

Select maintained cryptographic implementations after checking licenses,
`no_std` support, secret handling, known-answer coverage, and the exact algorithm
variants required. Avoid implementing AES or authentication primitives locally.
Record selected versions in `Cargo.lock` and keep host TPM dependencies optional.

Implement recovery-password validation and profile-specific derivation with
known-answer tests. Authenticate wrapped key records before accepting their
contents. Test wrong credentials, malformed lengths, altered authentication tags,
and valid credentials for a different volume. A filesystem signature is only a
structural check, not a substitute for key-record authentication.

Implement the data path independently of key acquisition:

- Expand unaligned reads to complete encryption units in bounded scratch space,
  decrypt, and copy only the requested range.
- Establish the exact sector/tweak numbering from format evidence, including
  nonzero partition starts and any relocated boot sectors or metadata regions.
- Reconstruct the logical plaintext boot area according to the profile; applying
  AES to every physical sector in place is not a sufficient mapping algorithm.
- Treat fully encrypted, used-space-only, and mixed conversion layouts separately.
  Do not infer plaintext zeros from sparse ciphertext storage or an allocation
  hole in the outer image.
- Preserve exact-read, EOF, empty-read, overflow, and bounds behavior of the
  upstream `ReadAt`. On failure callers discard output according to that contract.
- Support concurrent reads without sharing unsynchronized scratch buffers.
  Cache policy must be bounded and account for retained plaintext.
- Charge actual backend reads, scratch/cache memory, and expensive derivation
  work. Check cancellation between bounded work units.

Unwrapped-key authentication does not authenticate all plaintext sectors. Report
the actual integrity guarantees of the cipher profile and keep filesystem
validation independent. Avoid advertising authenticated volume contents.

## TPM 2.0 and swtpm integration

### Required state and policy

The socket transports TPM operations. Unlock requires the matching TPM state,
the selected volume's protector material, and satisfaction of its authorization
policy. Required factors may include boot measurements, a PIN, or a startup key.
Windows changes boot-related PCR state as execution progresses, so a TPM that
unlocked Windows during boot can reject a subsequent host-side unseal request.
These constraints are described in Microsoft's
[BitLocker countermeasures](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures).

Do not hard-code PCR 7 and 11 as a universal policy, treat PCR values as ordinary
writable registers, or assume a cold start with persistent state reconstructs a
boot-time authorization window. Decode the actual supported policy, selected
banks, and required authorization from qualified fixtures.

### Transport and ownership

swtpm exposes TPM command and control interfaces with different purposes. An
existing QEMU socket path may identify the control interface, and a compatible
integration must establish how TPM command traffic is carried. Follow the
[swtpm interface documentation](https://github.com/stefanberger/swtpm/blob/master/man/man8/swtpm.pod)
and use explicit endpoint configuration rather than guessing from a path.

Evaluate an existing TPM 2.0 stack and its swtpm transport before choosing a Rust
binding or direct implementation. The
[tpm2-tss project](https://github.com/tpm2-software/tpm2-tss) is a candidate host
stack, not a required portable dependency. Record the tested transport, native
libraries, and distribution requirements in the integration gate.

The provider must own an exclusive command session or receive an explicitly
coordinated transport. It must not concurrently inject commands into QEMU's
active TPM connection. Serialize session traffic, validate response framing and
lengths, bound allocations, set timeouts, and preserve TPM return codes.

Normal unlocking must not implicitly clear the TPM, reset PCRs, provision state,
change hierarchy authorization, or initialize a live VM's TPM. Startup and state
restoration belong to the test/VM lifecycle controller. Clean up only transient
objects and sessions created by this provider. Do not automatically retry failed
PIN attempts or replay commands after uncertain transport completion.

### Qualification spike before a support promise

Use a dedicated Windows VM to create a real TPM-only BitLocker protector and a
separate recovery-password protector. The recovery path supplies an independent
way to distinguish TPM policy problems from volume-decryption problems.

1. Record the Windows build, cipher, protectors, TPM version, PCR banks, firmware,
   Secure Boot configuration, and relevant boot event evidence.
2. Establish how to capture a coherent disk, firmware-variable, TPM persistent,
   TPM volatile, and VM execution state where required. A directory copy while
   swtpm is writing is not a valid snapshot protocol.
3. Prove ordinary Windows boot unlock using the matching VM and TPM state.
4. Identify a controlled policy-satisfying point for host-provider testing. Use
   an isolated fixture clone and a supported state handoff or restoration method.
   Prove that ownership transfer preserves the required TPM state; pausing the
   VM alone does not establish this.
5. Parse the Windows-created protector, execute the required TPM sessions, and
   authenticate the resulting BitLocker key chain through the portable engine.
6. Compare decrypted sectors and file contents with the recovery-password path
   and independently obtained Windows plaintext.
7. Restore pristine fixtures between cases and verify rejection for another TPM
   state, changed PCR policy, missing factor, malformed TPM response, and timeout.

If controlled handoff or protector interpretation is not yet demonstrated,
label the TPM provider experimental and keep portable recovery unlocking usable.
A generic TPM seal/unseal demonstration or a normal Windows boot does not prove
that `partmgr` can unlock a Windows-created protector through swtpm.

TPM+PIN follows as a separate milestone with credential encoding, authorization
session, lockout, and cleanup tests. Event replay or synthetic policy fixtures
may help isolate behavior in the laboratory, but must not be reported as proof
of a genuine firmware boot or matching native measured-boot execution.

## Filesystem and capture integration

Add a volume-envelope probe with outcomes for plaintext candidates, BitLocker
candidates, and unknown data. Keep `fs_image::ReadFormat` focused on inner
filesystems. Do not add BitLocker to `fs_core::Family` as though it were a
filesystem, and do not silently retry encrypted bytes as NTFS after unlock fails.

Require the caller to select a protector/provider, then pass the decrypted
reader into existing filesystem dispatch. A convenience API may compose these
steps, but must preserve typed failures, explicit credentials, and resource limits.

Retain the underlying source lifetime and bind decrypted-view identity to the
source, volume, selected metadata generation, and mapping profile. Use opaque
identifiers without deriving public identifiers from secret keys. Distinguish
ciphertext and plaintext views in receipts and cache keys.

Inherit source stability from acquisition. An immutable API, successful unlock,
or unchanged length is not a snapshot. Capture receipts should identify the
encrypted source, acquisition/snapshot information, decryption profile, and
inner filesystem validation. Mark whether an artifact contains ciphertext,
logical plaintext sectors, or extracted files. Never record keys or credentials.

Keep encrypted raw-copy operations separate from plaintext extraction. Raw
payload movement must not be presented as filesystem-aware BitLocker relocation
or resize support. The first unlocked reader exposes no `Storage` or `WriteAt`
capability, and it must not be accepted as authorization for durable edits.

## Validation matrix and evidence

| Gate | Required coverage | Evidence established |
| --- | --- | --- |
| Parser and public API tests | Truncation, overflowing ranges, unknown records, redundant-copy conflicts, limits, cancellation | Bounded handling of the tested inputs. |
| Crypto known-answer tests | Derivation, authenticated unwrap, sector transforms, wrong credentials and tampering | Agreement with independent expected vectors. |
| Reader contract tests | Arbitrary offsets, cross-sector reads, EOF, empty reads, nonzero partition starts, concurrent reads, sparse backing | Correct logical reads for the tested mapping profiles. |
| Portable builds | Default, no-default-features, portable BitLocker, host TPM feature combinations | Dependency and API portability. |
| Native Windows fixtures | Each supported cipher, protector, state, geometry, and metadata layout | Interoperability with the recorded Windows-created profiles. |
| swtpm provider gate | Real Windows TPM protector through this provider, policy/factor rejection, response errors, cleanup | Qualified TPM unlock behavior. |
| Firmware boot gate | QEMU/OVMF boot with matching TPM and Secure Boot configuration | Actual firmware/boot behavior for that fixture. |
| File capture gate | NTFS metadata, content hashes, streams, and supported security metadata compared independently | Correct capture for the tested source and filesystem profile. |

Generate small synthetic fixtures for boundary tests and use Windows-created
images for interoperability. Compare sector mappings and logical volume behavior
against an independent implementation such as
[libbde](https://github.com/libyal/libbde), after checking that implementation's
support for the exact fixture. Never generate both the expected and observed
bytes with the implementation under test.

Native fixtures should cover XTS key sizes, supported logical sector sizes,
full-volume and completed used-space-only encryption, differing partition
offsets, and metadata redundancy. Keep conversion-in-progress fixtures as
negative tests until supported. Avoid comparing captures made at different
times on a mutating Windows volume; capture coherent snapshots or quiescent
equivalent views and document any reserved regions excluded from comparison.

Add a BitLocker fuzz target for bounded inspection and a separate bounded
reader/mapping target using fixed test keys. Cover nested entries, redundant
metadata, offsets, and conversion state. Do not let fuzz inputs trigger unbounded
KDF work or contact a real TPM.

Store large private fixtures outside Git and check in reproducible generation
instructions plus manifests. Each native result should bind source hashes,
tool versions, commands, profile, expected failures, and compared artifacts.
Use generated test credentials; keep real recovery credentials and state secrets
out of logs and published fixtures.

Run repository-required checks after implementation changes:

```sh
cargo fmt -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

Add `cargo check --no-default-features --locked` and explicit portable-BitLocker
feature checks once feature names are finalized. Use the project development
environment and preserve shared Cargo configuration. Host test success does not
establish Windows servicing, capture correctness, TPM interoperability, or
firmware boot correctness; report these gates separately.

## Implementation milestones and completion criteria

1. **Format and dependency inventory.** Pin format references and independent
   tool versions, select initial profiles, document mapping and metadata-copy
   rules, evaluate crypto/TPM dependencies, and specify fixture generation.
   Complete when every initial-profile field and algorithm has an evidence source
   and unsupported cases have defined outcomes.
2. **Inspection.** Add bounded parsing, typed reports, volume probing, resource
   limits, negative tests, and fuzzing. Complete when inspection performs no
   unlock or mutation and ambiguous/unsupported states remain explicit.
3. **Decrypted reader.** Add the typed diagnostic FVEK path, sector transforms,
   logical mapping, and reader contract tests. Complete when independent sector
   comparisons pass for each claimed cipher and geometry.
4. **Recovery unlocking.** Add numerical recovery-password derivation and
   authenticated key-chain handling. Complete when Windows-created fixtures
   unlock and wrong credentials fail without publishing an unlocked reader.
5. **Filesystem integration.** Connect decrypted views to `ReadImage` and NTFS,
   preserve stability/provenance, and compare independent file captures. Complete
   when both direct reads and existing pipeline operations pass their native gate.
6. **TPM feasibility and provider.** Run the swtpm spike, implement the chosen
   transport and TPM policy path, and qualify Windows-created TPM-only fixtures.
   Complete only when this provider unseals and reads the expected volume under
   controlled matching state and rejects the negative cases.
7. **Additional protectors.** Add TPM+PIN, external key, password, and clear-key
   profiles one at a time. Publish only the profiles with independent evidence.
8. **Release qualification.** Run the full feature matrix, fuzz regressions,
   native/TPM/capture gates, and document the exact support matrix and examples.
   Add benchmark results for sequential reads, random 4 KiB reads, concurrency,
   scratch/cache memory, and unlock latency. Compare with the same unencrypted
   source path; reads must not require extracting the whole volume or repeating
   the TPM operation per sector.

Milestones 1 through 5 form the portable read release. Milestone 6 is required
before advertising swtpm unlock. Milestone 7 expands support without holding the
initial qualified profiles open indefinitely. Expose limitations in capability
reports and documentation rather than treating an entire family as supported.

## Recoverable encrypted writes

Add an opt-in `bitlocker-write` feature implying `bitlocker`. Use an owned
`BitLockerSession<S, J>` over exclusive `Storage` and independent recovery storage.
Do not turn `UnlockedVolume` into a writable handle or retain an immutable alias
of the mutable backend inside the session. Inspect and unlock through the owned
backend, then keep its length, metadata selection, mapping, and key schedules
bound to that session.

For the initial completed full-volume XTS profile:

1. Validate the entire requested logical range before preparing any writes.
   Reject direct writes to synthesized metadata/backup regions. Logical boot
   writes map to the relocated physical boot sectors.
2. Expand partial writes to encryption-unit boundaries, decrypt each affected
   sector, apply the replacement, and encrypt with its physical volume-relative
   tweak. Keep plaintext scratch bounded and zero it on every exit.
3. Produce exact old/new ciphertext patches at physical offsets. Capture
   metadata and geometry preconditions so a plan cannot be replayed against
   another mapping, protector generation, or bounded volume.
4. Use the external undo protocol in `fs_undo` for the ciphertext transaction.
   Persist and flush the old ciphertext before target mutation; verify target
   replacement and flush before publishing a terminal marker.
5. Retain a sticky recovery obligation after any uncertain target/journal write
   or barrier. Refuse fresh edits until explicit recovery and reinspection.
   Raw ciphertext rollback must not require the recovery password or FVEK.

The writer needs sector encryption in `bitlocker_crypto`, owned-storage metadata
inspection in `bitlocker_disk`, and a separate mutable module. Factor reusable
decoding away from the immutable `ReadAt` acquisition path without weakening
either contract. Retained plans contain ciphertext, not plaintext file payloads.

Filesystem transactions require a deliberate composition rule: placing the
current filesystem undo store outside a decrypted `Storage` adapter would save
plaintext. Initially expose BitLocker ciphertext transactions and explicit
logical replacement plans; qualify filesystem editor integration only after its
journal is encrypted or its transaction is translated to ciphertext patches.
Do not imply general NTFS editing merely because encrypted sector writes work.

Keep encryption conversion, resizing, protector changes, and metadata updates as
separate operations with native evidence. Tests must include unaligned and
cross-sector patches, relocated boot writes, reserved-region rejection, stale
bindings, short/torn writes, every target/journal durability cut, cold retry,
and exact old-or-committed ciphertext recovery. Compare native Windows plaintext
and filesystem consistency after edits, independently of the reader.

## New volumes and complete disk images

Add a `bitlocker-create` feature implying the portable BitLocker components it
uses. Separate the volume authoring plan from disk layout and host provisioning.
Accept caller-supplied cryptographically secure randomness, unique identifiers,
protector configuration, filesystem input, geometry, and limits. No fixed test
keys or deterministic production defaults are allowed.

The creator must generate VMK/FVEK material, construct authenticated protector
records, preserve nonce uniqueness, allocate redundant metadata and relocated
boot regions, and stream encrypted sectors into a new exclusive staging target.
Publish the image only after its length, partition tables, volume metadata,
decryption, and inner filesystem validate. Report progress and interrupted
staging explicitly; final host publication requires its own durability barrier.

BitLocker-reserved regions must also be allocated in the inner filesystem.
Appending metadata beyond a claimed NTFS length or overwriting arbitrary free
clusters is not sufficient: future filesystem allocation could overwrite them.
The current NTFS code is a reader, not a complete NTFS formatter or reservation
editor. Use native Windows formatting/BitLocker provisioning for the first
interoperable creation gate, or accept a qualified prepared filesystem image.
Portable native authoring remains a separate formatter/reservation milestone.
Extend the current reader's mapping support to match the native creation fixtures
before claiming that newly created images work through the portable engine.

### Encrypted data disk

Produce a protective MBR, primary and backup GPT, an explicit Windows-compatible
layout policy, and one or more aligned encrypted data volumes. Provision NTFS
initially, with a recovery-password protector; qualify additional filesystem and
protector profiles independently. Include an MSR where the selected Windows GPT
policy requires it. No ESP or Windows installation is required for this profile.

Acceptance requires Windows attaching the image, recognizing and unlocking its
data volumes, reading/writing known files, and detaching cleanly. Compare GPT
inspection and decrypted content with independent tools, and test publication
cuts on a disposable staging target.

### Bootable Windows system disk

Create the following default partition order:

```text
protective MBR and primary GPT
    -> FAT32 EFI System Partition, unencrypted
    -> Microsoft Reserved partition
    -> NTFS Windows partition, BitLocker-encrypted
    -> NTFS Windows RE partition, separate and unencrypted
    -> optional encrypted data partition
backup GPT
```

Use an explicit layout policy with configurable sizes and checked alignment.
Size the ESP for the actual sector geometry and boot files; size WinRE from the
selected `winre.wim`, customizations, required servicing free space, and filesystem
overhead. Assign the native recovery type and required attributes. Follow the
[Microsoft UEFI/GPT partition requirements](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/configure-uefigpt-based-hard-drive-partitions)
and [BitLocker deployment requirements](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/planning-guide).

Disk geometry alone cannot supply Windows. The build API must receive a Windows
deployment image or a qualified prepared Windows volume, EFI boot payloads, and
WinRE material. The host workflow must apply the OS, generate BCD for the final
partition identities, install EFI boot files, register WinRE, and verify those
bindings. Native DISM, BCDBoot, REAgentC, and BitLocker provisioning belong in a
Windows deployment adapter or controlled VM workflow; tool and privilege failures
must be causal and observable. Do not report a layout or copied WIM as bootable.

For TPM-protected OS images, provision the protector against the intended VM's
TPM and qualified boot environment. Retain an explicit recovery protector and
verify that no unintended clear-key protector remains at publication. Rebinding
to another TPM is a provisioning operation, not an image-copy side effect.

Acceptance requires QEMU/OVMF boot into Windows, actual TPM/recovery unlock,
WinRE launch and its documented recovery access path, and native consistency
checks after write/reboot cycles. Keep disk and firmware/TPM state as distinct
artifacts linked by a manifest. Firmware boot evidence belongs to the separate
integration gate, not to host unit tests.

## UEFI variables and imported swtpm state

UEFI variables and TPM state are different artifacts even when both are called
NVRAM. OVMF variables hold firmware settings such as Secure Boot policy and boot
configuration. They can help reproduce a compatible measured boot, but are not a
normal BitLocker VMK/FVEK credential. The encrypted volume's TPM protector and
matching TPM state are still needed. The
[OVMF variable-store documentation](https://github.com/tianocore/edk2/blob/master/OvmfPkg/QEMU_PV_VARS.md)
describes the firmware variable store; Microsoft's
[BitLocker countermeasures](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures)
describe the measured-boot restrictions on key release.

Provide distinct host unlock configurations:

| Input | Provider behavior |
| --- | --- |
| Live swtpm endpoint | Execute the selected TPM protector policy over an exclusive command transport. |
| Offline persistent swtpm state | Import a disposable copy into an isolated emulator and establish the required policy state before unsealing. |
| Coherent persistent and volatile state snapshot | Restore supported state with compatible tooling and verify policy/PCR state before unsealing. |
| OVMF variable store | Supply to the VM boot environment; never treat it as a TPM state blob or volume key. |

The first offline provider should launch an isolated swtpm instance against an
explicit state copy and use the same command provider as the live socket path.
An optional in-process libtpms backend can follow after state-envelope/version
compatibility and lifecycle behavior are demonstrated. Do not implement generic
key scanning of TPM state files or assume that a persistent blob contains an
exportable plaintext BitLocker VMK.

Persistent state preserves the TPM identity/root secrets and NV data, but alone
does not establish the PCR conditions of an earlier boot. A compatible volatile
snapshot can preserve more runtime state; its capture time must satisfy the
actual protector policy. A snapshot taken after Windows advanced PCR 11 cannot
be described as equivalent to the boot-time unseal window. Full VM execution
state may also be needed when resuming the original boot sequence.

swtpm supports separate persistent and volatile state artifacts, and optional
at-rest state encryption and migration encryption. Import requires the matching
key material when those protections were enabled. In its control tooling the
`savestate` blob specifically depends on TPM 1.2 `TPM_SaveState`; do not use that
name as a generic TPM 2.0 snapshot guarantee. Follow the
[swtpm state options](https://github.com/stefanberger/swtpm/blob/master/man/man8/swtpm.pod),
[state export/import interface](https://github.com/stefanberger/swtpm/blob/master/man/man8/swtpm_ioctl.pod),
and [QEMU TPM migration contract](https://www.qemu.org/docs/master/specs/tpm).

Require an explicit artifact manifest: disk generation, firmware code/version,
variable store, TPM version, swtpm/libtpms versions, state kind, encryption-key
requirement, snapshot coherence, and selected protector identifier. Capture
through the supported lifecycle/export mechanism; never infer coherence from
copying an active state directory. Restore only into disposable exclusively
owned state, preserving the original evidence artifacts.

Qualify live and imported-state providers separately with a Windows-created
TPM protector. Test matching persistent state with incompatible PCRs, a wrong
TPM, a post-boot volatile snapshot, mismatched snapshot generations, incompatible
state formats, missing state-decryption keys, and transport failures. Normal
unlocking must continue to avoid implicit TPM clear or PCR reset.

## Additional implementation order

After native read qualification, advance the requested targets in this order:

1. Own mutable backends and factor portable disk decoding for them.
2. Implement sector encryption and recoverable ciphertext transactions.
3. Create and qualify a complete encrypted data disk using native provisioning.
4. Assemble and qualify the Windows ESP/MSR/OS/WinRE disk workflow.
5. Implement the live TPM command provider and isolated state-import provider;
   qualify TPM provisioning and boot for the system-disk workflow.
6. Add portable native volume authoring, further mapping/protector profiles,
   and qualified filesystem transaction integration.

Both disk profiles are required. Native Windows deployment is an explicit first
implementation route for compatible NTFS/BitLocker authoring, not a substitute
for the portable creator milestone. Write correctness, image creation, TPM
unsealing, Windows boot, and recovery each need their own recorded acceptance.
