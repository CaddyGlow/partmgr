# Native execution evidence (2026-10-09)

Dedicated disposable `bitlocker-native-1009`, Windows build 10.0.26200.0,
QEMU/OVMF with Secure Boot, inherited `win11-secure` base and dedicated swtpm.
Artifacts reside outside the repository under
`/data/cache/partmgr-bitlocker-native/`; credentials are mode 0600 host files,
separate from manifests. No unrelated VM was modified.

## Data fixtures

Windows created fixed 256 MiB VHDs, NTFS with 512-byte sectors/4096-byte clusters,
full XTS encryption, independent random numerical recovery protectors, and a
1 MiB deterministic `oracle.bin`. Both reached FullyEncrypted/100%/Protection On,
passed native hash comparison plus an encrypted file write, then detached.

| Artifact | SHA-256 |
| --- | --- |
| `xts128/disk.vhd` | `43bbcbc9014b0b74e88858ae66c43d7e3bf614070112611af0e87eca00cfdc2d` |
| `xts256/disk.vhd` | `f8c38a4646048eef4be047b8e4bb9e3d93e5f99f149b5a74580dbcb17110ca83` |
| native `oracle.bin` | `4b1e40b2a9f438e6aa04c9b4428e82424b88a1febe5ebfd3be1e0e981fe6902a` |

Both original partition views start at 33554432 and have length 234815488. These
first fixtures have two MSR entries because DiskPart `convert gpt` created one
before the script's explicit MSR; the generator was corrected to use the native
implicit MSR. This layout discrepancy does not change the bounded data-volume
oracle and is not evidence for the intended final layout policy.

The XTS128 guest copy was subsequently mounted/unlocked to capture logical-sector
oracles and run `fsutil dirty query` plus `chkdsk /scan`; original host ciphertext
was preserved unchanged. Windows reported NOT Dirty before and after its scan,
found no filesystem errors, then locked/dismounted and detached successfully.
Thus metadata/filesystem housekeeping on the guest copy can differ from the
original host fixture. No later guest hash is substituted for the original hash.

Six 65536-byte native plaintext reads are in `xts128/samples/`, with hashes in
`samples.json`. Logical offsets 35651584, 62218240, 88780800 (metadata), 35717120
(relocated boot reservation), and 35725312 (extended reserved area) are all zero;
each SHA-256 is `de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31`.
The logical boot sample at 0 has hash
`ea20185cfa33f479ff75e90bee49cf23b1e4e574e69f57a31bf05731c974bd6e`.
Native `fsutil file queryextents` reports oracle.bin VCN 0, 256 clusters, LCN
0x7d3. At 4096 bytes/cluster, file offset 123 maps to logical byte 8204411.

## System staging

Native full-volume OS encryption was rejected with HRESULT 0x803100A5 because the
virtio disk reports thin provisioning. The same explicitly created recovery and
TPM-only protectors were retained, and an explicit used-space-only attempt reached
FullyEncrypted/100%/Protection On. This is a separate unsupported portable mapping
profile; it is not evidence for full-volume OS reads.

`system/` contains the non-secret manifest, native REAgentC information, encrypted
boot sector and three bounded physical-disk metadata copies. They were acquired
live after conversion completion, so they do not form a coherent disk/TPM/VM
snapshot. Partition offset is 449839104 and length is 67445456896. TPM metadata
parsing and host policy satisfaction require their own evidence.

The WinPE deployment adapter is syntax-checked but has not been executed against
a Windows deployment WIM. No WinRE launch, portable OS decryption, host TPM
unseal, interrupted publication, or complete disk-image creation qualification is
claimed by these scripts or manifests.

The host ignored `bitlocker_native` gate passed for the original XTS128 artifact:
recovery-password authenticated unwrap, wrong-password rejection, exact native
boot/reserved-sector sample comparison, NTFS open and the independent oracle file
SHA-256. This required correcting native metadata CRC-trailer/key-record handling,
extended reserved-region mapping and the benign NTFS 0x0080 short-name/tunneling policy flag.

The original XTS256 artifact also passed the ignored recovery/wrong-password/NTFS
file hash gate. The system VM then rebooted to the Windows login screen without
recovery input. `system/after-reboot.json` records a changed boot time
(1791578639500 → 1791579250500 milliseconds since epoch), Secure Boot true,
FullyEncrypted/Protection On and exactly RecoveryPassword + Tpm protectors.
This proves native Windows boot unlock for this used-space-only VM profile; it
still does not establish host-provider TPM unseal or portable used-space reading.

Repository validation after the implementation: `cargo fmt -- --check`, strict
all-target/all-feature Clippy, full all-feature tests (742 passed, 84 ignored),
no-default-feature base/read/write checks, and the BitLocker fuzz seed smoke gate
passed. These host gates remain separate from Windows and firmware evidence.

Native Windows acceptance of the host-written ciphertext passed. Input edited VHD
SHA-256: `cf5f7fb33ce32c71b1040a9e4ec2e6a146ea6106e1cbcd2f7c17bdf3d75969bc`.
The host replaced 32 bytes with 0xA7 at logical volume offset 8204411 (oracle.bin
file offset 123). Windows recovery unlock succeeded, and its independent file
SHA-256 was `02f2be8ab64a6e1f7331d473feff6f9b8ce24ddf4e6bf69ca2dd1c4bea2dcde6`.
Native `chkdsk /scan` returned zero; explicit lock/dismount and detach succeeded.
The acceptance manifest and native logs are in `edited-acceptance/`. This proves
one native encrypted data-write case; exhaustive interruption coverage remains a
separate synthetic recovery gate.

The corrected data generator was executed again as `xts128-final/`. Native
provisioning, encrypted write/read, and clean detach completed; the transferred
whole VHD hash verified as
`42bb174925f0102d7fb18b0c5cc7c75c29efdd5236e304ebe4ed2ea78ae6b360`.
Independent GPT inspection shows exactly one MSR and one Basic Data partition.
The encrypted volume offset is 16777216, length 251592704; its oracle file has the
same expected native SHA-256. A transfer timeout left a partial artifact, which
was resumed at its known byte count and only published after the complete hash
matched the native manifest. QGA helper calls now coordinate with a host lock;
external QGA clients still require exclusive coordination.

The final single-MSR fixture also passed the portable native recovery,
wrong-password rejection and NTFS oracle-file SHA-256 gate. All five integration
PowerShell scripts passed the native Windows PowerShell parser after the final
edits; both Python helpers passed bytecode compilation.

Cleanup: Windows accepted orderly shutdown, the dedicated VM launcher exited
with status 0, and its QMP socket disappeared. Disposable disk/OVMF/TPM artifacts
and all qualification fixtures were retained; no unrelated instance was stopped.
