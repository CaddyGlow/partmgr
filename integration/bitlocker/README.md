# Native BitLocker gates

These scripts operate only on disposable staging artifacts. They do not implement
a portable NTFS formatter, manufacture TPM policy evidence, or establish boot
success from a disk layout. Recovery secrets are separate from manifests; protect
fixture directories and never commit the generated images or credentials.

## Data fixture

Run elevated in a dedicated Windows VM:

```powershell
powershell -ExecutionPolicy Bypass -File provision-data.ps1 -OutputDirectory C:\bitlocker128 -Cipher XtsAes128
powershell -ExecutionPolicy Bypass -File provision-data.ps1 -OutputDirectory C:\bitlocker256 -Cipher XtsAes256
```

Each invocation creates a fresh fixed VHD, GPT/MSR/NTFS layout, full-volume XTS
encryption and a Windows-generated recovery protector. It writes a deterministic
1 MiB oracle, verifies the native hash after encryption, writes another file, and
detaches before hashing ciphertext and publishing `manifest.json`. An existing
output directory or occupied drive letter is refused. `recovery.secret` is only
written to the administrator/SYSTEM-only output directory. Failure leaves staging
and logs available, but no successful manifest.

Use `qga-file.py SOCKET pull LOCAL GUEST` for a stopped-use fixture's `disk.vhd`,
`manifest.json`, and `recovery.secret`. The QGA endpoint must belong to the
explicitly selected disposable guest. Downloads use exclusive mode-0600 files;
partial downloads remain incomplete and must not be used as qualification input.
The VHD's raw disk starts at byte zero; the native Rust test bounds the selected
partition, excluding the footer.

```sh
python3 integration/bitlocker/qualify.py /path/to/fixture -- \
  nix develop --no-write-lock-file path:/home/rick/projects-caddy/nix-dev-shells/default -c \
  cargo test --features bitlocker --locked --test bitlocker_native -- --ignored
```

The runner checks manifest completion, bounds and SHA-256 before invoking the
explicit host command. The Rust gate verifies recovery unlock, rejects a wrong
password, reads the inner NTFS file and checks its independent Windows hash. This
is a data-volume read gate; it does not qualify encrypted editing or capture.

## Windows system staging

`deploy-windows.ps1` runs in WinPE with Storage/PowerShell components, explicit
Windows WIM/index and WinRE WIM inputs, and a **blank RAW non-system target disk**.
It refuses to erase existing disks. It creates ESP/MSR/Windows/WinRE, applies the
image with DISM, installs EFI files/BCD with BCDBoot, registers the offline WinRE
path and sets recovery GPT attributes. The default 300 MiB ESP supports the
minimum 260 MiB 4 KiB-sector requirement; WinRE sizing reserves at least 512 MiB
beyond the supplied image. A failed deployment remains staging.

After booting that disk in the intended disposable QEMU/OVMF/TPM environment,
run `provision-system.ps1 -DisposableVm -EvidenceDirectory C:\system-evidence`.
It enables WinRE, requires an already-ready TPM, keeps an independently generated
recovery protector, enables full XTS encryption, and checks the exact active
TPM/recovery protector set. It never clears or provisions TPM hierarchy state.
No automatic reboot or TPM state copying occurs.

Both manifests explicitly leave unperformed firmware, WinRE and host TPM-unseal
gates false. To qualify publication, separately record reboot into encrypted
Windows, boot event/PCR banks, recovery unlock, WinRE launch, native consistency
checks and controlled disk/OVMF/swtpm snapshot provenance. Shut down coherently
before persistent-state copying; a live directory copy or paused QEMU alone is
not a TPM handoff protocol. Offline deployment and encryption scripts have not
by themselves established those gates.

Primary references: Microsoft's [UEFI/GPT partition guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/configure-uefigpt-based-hard-drive-partitions)
and [BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide).

Some VM storage reports thin provisioning; Windows rejects full-volume encryption
there with `0x803100A5`. The system adapter accepts explicit `-UsedSpaceOnly` for
that separate fixture profile and records it in the manifest. This does not
qualify the portable reader's used-space mapping. A failed full-encryption attempt
can already have created protectors; inspect the retained state before any retry.

`capture-oracle.ps1` takes explicit logical offsets from an already unlocked native
volume and emits bounded plaintext samples plus SHA-256 metadata. Samples are
sensitive plaintext. `qualify.py` passes a fixture's `samples/samples.json` to the
Rust gate when present.

For host encrypted-write acceptance, transfer the **new edited VHD** into the
Windows guest and run `verify-data.ps1` with that path, the separate recovery
secret file, the expected changed `oracle.bin` SHA-256 and a new evidence directory.
It records the exact input ciphertext hash, unlocks, checks the native file hash,
runs `chkdsk /scan`, locks/dismounts, and cleanly detaches before publishing a
success manifest. Windows may update filesystem housekeeping during this check;
the input hash identifies the host-produced artifact before that native activity.

## Experimental TPM/swtpm provider gates

The opt-in Rust `bitlocker-tpm` feature exposes strict native TPM-only decoding,
a raw TPM2 command transport, authenticated policy sessions and an isolated
persistent-state importer. The command endpoint and emulator control endpoint
are distinct. A caller must explicitly own/co-ordinate the command connection;
never connect this provider to QEMU's active TPM. `ImportedSwtpm` requires a
stopped source state directory and a fresh private destination; it copies only
`tpm2-00.permall`. `Startup::Clear` cold-starts the copy, while `Startup::Caller`
leaves TPM startup to the lifecycle caller. Neither reconstructs measured boot.
Drop/shutdown affects only the owned child and retains its disposable artifacts.

Install/provide `swtpm` and `tpm2-tools` independently of the Rust portable build.
The executed laboratory used swtpm 0.11.0 and tpm2-tools 5.7. Native library
requirements come from those executables; the Rust transport itself does not
link libtss2 or libtpms. Use short absolute output paths for UNIX socket limits.

Create a real synthetic PolicyAuthValue→PolicyPCR fixture and exercise matching
copied state, changed-PCR rejection and wrong-TPM rejection:

```sh
python3 integration/bitlocker/swtpm-gate.py \
  --swtpm /path/to/swtpm --tools /path/to/tpm2-tools/bin \
  --output /data/cache/new-tpm-fixture
PARTMGR_SWTPM=/path/to/swtpm \
PARTMGR_BITLOCKER_TPM_FIXTURE=/data/cache/new-tpm-fixture \
  cargo test --features bitlocker-tpm --locked --test bitlocker_tpm_native \
  imported_swtpm_policy_auth_value_unseals_and_preserves_source -- --ignored
```

Output contains sensitive TPM state and synthetic secrets under a private
0700 directory. `secret.bin` is a 44-byte native-shaped VMK record. The fixture
uses persistent parent 0x81000001 and explicit SHA256 PCR7+11; these are fixture
parameters, not universal BitLocker policy assumptions.

The Windows laboratory additionally captured a real native TPM-only protector
and the Windows measured-boot log. The provider's native gate authenticates the
wrapped FVEK independently of filesystem mapping, so the OS fixture's unsupported
used-space mapping never becomes an unlocked reader.

`extract-tpm.py` exports bounded native TPM2B public/private blobs and policy
inputs from the selected captured Windows metadata. The required replay fixture
files are `native-sealed.pub`, `native-sealed.priv`, and `native-pcr.digest`;
the root Rust native gate also consumes captured `encrypted-boot.bin` and
`metadata-*.bin` files. The persistent parent must be established independently
(e.g. read capabilities and verify Load on an isolated copy); metadata does not
supply a guessed parent handle.

For explicitly authorized **laboratory replay**, the harness below parses a
Windows log with `tpm2_eventlog`, finds the event prefix matching the protector's
PCR digest, cold-starts a private copied TPM state and extends only that copy.
It never accepts a live endpoint, touches original state, clears a TPM, or claims
that replay is genuine measured execution. The root positive gate then unseals
through the Rust provider and authenticates the native FVEK:

```sh
PARTMGR_BITLOCKER_TPM_EVIDENCE=/path/to/native-metadata \
PARTMGR_BITLOCKER_LENGTH=67445456896 \
python3 integration/bitlocker/swtpm-replay.py \
  --swtpm /path/to/swtpm --tools /path/to/tpm2-tools/bin \
  --source-state /path/to/stopped-tpm-directory \
  --event-log /path/to/Windows/MeasuredBoot/0000000003-0000000000.log \
  --fixture /path/to/native-metadata --parent-handle 0x81000001 \
  --pcrs 7,11 --output /data/cache/new-native-replay -- \
  cargo test --features bitlocker-tpm --locked --test bitlocker_tpm_native \
  windows_native_tpm_authenticates_wrapped_fvek -- --ignored
```

The harness supplies the owned command socket and explicit parent to the engine
command, records input hashes and replay prefix, verifies original persistent
state is unchanged, and stops its child. Live VM handoff, volatile snapshot
restoration, TPM+PIN and portable reading of this OS conversion profile remain
separate unqualified gates. OVMF variables are boot inputs, never credentials.
