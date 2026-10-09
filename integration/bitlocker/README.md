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
