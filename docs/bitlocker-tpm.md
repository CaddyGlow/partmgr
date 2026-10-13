# Experimental TPM and swtpm providers

Enable `bitlocker-tpm` to build the experimental Windows TPM-only parser, TPM 2.0
command provider and Unix swtpm adapters. The feature implies `bitlocker` and
`std`; portable BitLocker reads remain available without it. This is a narrow
implementation with separately recorded synthetic, native and boot evidence.
A matching TPM and PCR state are required. Merely importing persistent state
does not recreate the Windows boot-time unseal window.

## Architecture and supported profile

`bitlocker_tpm` decodes the observed Windows 26200 TPM-only version-five sealed
object. It checks the complete SHA-256 `PolicyAuthValue` then `PolicyPCR` policy,
including the stored PCR digest and matching selection masks. TPM+PIN, startup
keys, other algorithms, unknown policy sequences and alternate datum versions
are rejected. The [format and evidence notes](bitlocker-tpm-format.md) describe
all accepted fields and the retained auxiliary-record boundary.

`bitlocker_tpm_host::Tpm2Provider` sends bounded TPM commands over an exclusive
`CommandTransport`. It loads the sealed object under the caller-selected parent, starts a
policy session, executes the verified policy, authenticates the unseal response
and flushes allocated handles. TPM return codes and cleanup obligations remain
typed. Transport uncertainty fences the provider instead of replaying commands.
The lower-level engine also handles a separately explicit bounded PolicyOR
profile; the Windows protector API uses only its validated native sequence.

`bitlocker_swtpm::ImportedSwtpm` restores an explicitly supplied state copy into a
new disposable instance directory and exposes its command socket. It preserves
the source artifacts. Lifecycle startup is explicit and separate from normal
unsealing. `UnixCommandTransport` can instead connect to a live swtpm command
socket already assigned exclusively to this operation.

The stack evaluation considered `tss-esapi` with `tpm2-tss`, which would provide
a broader ESAPI but require native libtss2. This first implementation uses the
small bounded wire profile described above and published Rust cryptographic
dependencies. It does not implement general TPM management, salted sessions,
parameter encryption, PIN authentication or arbitrary parent authorization.
The [TPM reference implementation](https://github.com/microsoft/ms-tpm-20-ref)
and [tpm2-tss wire types](https://github.com/tpm2-software/tpm2-tss/blob/master/include/tss2/tss2_tpm2_types.h)
provide the command/response contracts.

## Explicit acquisition and calls

The command transport must be trusted and exclusive: unsealed key material
crosses this channel without parameter encryption. Never connect alongside a
running QEMU client. A filesystem path to a socket is not itself proof of
ownership or of a matching TPM. Use finite command deadlines.

The caller supplies the selected protector identifier, the matching persistent
storage-parent handle, and a fresh cryptographically generated 32-byte nonce for
every operation. Parent handles are not inferred from the encrypted volume.
Only empty parent authorization and empty (or TPM-trimmed all-zero) object
authorization are supported. PolicyAuthValue is still executed and authenticated;
additional factors are never silently dropped.

For an already initialized, exclusively owned Unix command endpoint:

```rust,ignore
use partmgr::bitlocker_tpm_host::{Tpm2Provider, UnixCommandTransport};
use std::time::Duration;

let transport = UnixCommandTransport::connect(command_socket, Duration::from_secs(5))?;
let mut provider = Tpm2Provider::new(transport);
// nonce is a fresh cryptographically generated [u8; 32]; parent is the verified
// persistent storage-parent handle for this specific TPM and protector.
let reader = volume.unlock_tpm(protector_id, &mut provider, parent, &nonce)?;
```

On Unix, `ImportedSwtpm::import(ImportConfig { executable, source_state,
instance_directory, startup, timeout })` creates a private disposable copy.
Choose `Startup::Clear` explicitly for cold PCRs, or `Startup::Caller` to perform
initialization separately. Drop command clients before calling `shutdown()`.
The importer retains its private state/log directory for caller cleanup. The
generic command engine also accepts a caller-implemented `CommandTransport`;
this release supplies no physical TPM device or Windows TBS transport adapter.

The volume API exposes three distinct operations:

- `tpm_protector(id)` performs bounded parsing and policy validation only.
- `authenticate_tpm(id, provider, parent, nonce)` unseals the VMK and authenticates
  the wrapped FVEK, returning key evidence without publishing keys or a reader.
- `unlock_tpm(id, provider, parent, nonce)` first checks logical-read support,
  then authenticates the key chain and returns the existing read-only view.

The separate authentication operation allows checking a TPM protector on an
otherwise unsupported volume mapping. It must not be reported as used-space-only
read support. A failed unlock does not trigger a clear-key, password or raw
filesystem fallback. Keys and credentials must not appear in diagnostics,
receipts or fixture manifests.

## State and evidence gates

The [swtpm interface documentation](https://github.com/stefanberger/swtpm/blob/master/man/man8/swtpm.pod)
distinguishes command/control channels, persistent and volatile state, and state
encryption. Current import support is intentionally limited to the state modes
accepted by its API; unsupported encrypted or unknown artifacts fail explicitly.
OVMF variables remain boot-environment inputs, never a key credential. The
[QEMU TPM migration contract](https://www.qemu.org/docs/master/specs/tpm.html)
is the reference for coherent VM/emulator capture. Do not infer snapshot
coherence from a directory copied while an emulator was running.

`integration/bitlocker/swtpm-gate.py` prepares a synthetic sealed-object fixture
using swtpm and tpm2-tools. Successful fixture preparation establishes that the
selected emulator can load and unseal that synthetic policy. The opt-in Rust
test in `tests/bitlocker_tpm_native.rs` exercises the imported-state provider,
response authentication, strict unsealed-record parsing and the complete
VMK-to-FVEK key chain, including a tampered FVEK negative case. It also compares
the source state before and after import. This Rust full-chain gate passed for
the generated synthetic fixture, including `authenticate_tpm`, `unlock_tpm` and
the tampered-FVEK authentication failure. Synthetic objects are not Windows
interoperability evidence.

The Windows-created system fixture has separately demonstrated a native
TPM-protected reboot into Windows. Its metadata matches the parser's policy
profile. The Rust command provider successfully unsealed that native object,
verified its response HMAC, and authenticated the wrapped FVEK in an isolated
copied-state experiment. Seven measured-boot PCR7 events were explicitly replayed
to reproduce the protector's PCR digest, with PCR11 still zero. Cold PCRs were
rejected by the Rust provider; an unrelated TPM rejected the native object.
See [the evidence record](../integration/bitlocker/EVIDENCE.md) and
[reproduction instructions](../integration/bitlocker/README.md).
This qualifies that laboratory replay case, not live VM handoff, volatile-state
restoration, physical TPM adapters, or reading the system fixture's unsupported
mapping. A Windows boot does not itself qualify the host provider. Record mismatched TPM/PCRs,
missing factors, post-boot state, incompatible generations/formats and transport
failures separately. Host tests do not establish firmware boot, WinRE access,
Windows servicing or capture correctness.
