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

## Experimental TPM/swtpm qualification (2026-10-09)

Tools: swtpm executable reports 0.11.0 (Nix package
`swtpm-0.10.1-unstable-2026-05-21`), tpm2-tools 5.7. The optional Rust importer and
command provider do not link those tools' native libraries into the portable
BitLocker build.

The executed `swtpm-gate.py` fixture is
`/data/cache/partmgr-tpm-synthetic-4`. It creates a real SHA256 keyed-hash sealed
44-byte native-shaped key record with attributes 0x412 and
PolicyAuthValue→PolicyPCR, PCR7+11, parent 0x81000001. Native tools unsealed using
an imported matching state copy, rejected a changed PCR7, and rejected the blob
under an unrelated TPM's parent. Original persistent state stayed unchanged.
Synthetic policy fixtures do not qualify a Windows-created protector by
identity alone.

The real Windows protector was independently loaded under the original stopped
VM state's copied persistent parent 0x81000001. Other native persistent parents
0x81000002/0x81010001 were unsuitable. Cold-start SHA256 PCR7/PCR11 were zero;
a valid PolicyAuthValue→PolicyPCR session on those values failed native Unseal
with TPM return 0x99d (policy check failed). A distinct TPM at the same persistent
parent handle rejected the Windows blob with TPM 0x1df (integrity check failed).
Evidence: `/data/cache/partmgr-tpm-native-3` and `partmgr-tpm-native-wrong`.

For measured-boot inputs, a separate VM used a new overlay with the original
stopped disk as read-only backing, and private copied firmware/TPM state. It
booted Windows, exported `C:\Windows\Logs\MeasuredBoot` logs, then shut down
orderly with launcher status 0. Original OVMF and TPM hashes were verified
unchanged; `/data/cache/partmgr-tpm-replay/shutdown.json` records cleanup.

The captured boot3 log SHA-256 is
`d534a0e445d8fcbd67ebfad4d8ae623d06e137dbd5e0f6c76f0ea5dc2aa72a10`.
`tpm2_eventlog` decoded it. Seven SHA256 PCR7 extensions through event 28,
with PCR11 still zero, reproduce the exact native protector's combined PCR digest.
Later log events extend PCR11 beyond that authorization point. This explains why
cold-start state alone and the ordinary post-boot state are insufficient.

Explicit replay into an isolated imported copy of original permanent state
SHA-256 `e94b926671184233e6b8524b6288d65c81073199b3e5060ff045654c48a80450`
allowed native tools to unseal the Windows-created 44-byte VMK record. Its observed
header is `2c0000000100000003200000`; the independently published artifact uses
five in the second 16-bit word, so the strict decoder accepts those two observed
values while retaining all other checks. The returned key is never included in
ordinary logs or reports.

The committed `swtpm-replay.py` reproduced this native-tool success and clean
shutdown at `/data/cache/partmgr-tpm-native-script`; it verified the original
persistent-state hash remained unchanged. Its manifest explicitly labels
laboratory replay, `firmwareBoot=false` and `liveVmHandoff=false`. This proves
matching state and reconstructed policy can release the native sealed object;
it is not a live boot-time handoff, volatile snapshot restoration or proof that
arbitrary Windows policies are supported.

The Rust `windows_native_tpm_authenticates_wrapped_fvek` gate passed against that
isolated replayed endpoint: native datum parsing, TPM policy/HMAC session,
authenticated unseal response, VMK decoding and authentication of the native
wrapped FVEK all succeeded. It reported authenticated TPM key evidence and still
refused an unlocked reader for the unsupported OS mapping profile. Thus this gate
qualifies the observed native TPM-only key chain without widening volume-mapping
support or claiming firmware handoff.

The complete repository replay harness plus Rust gate was then rerun as one
command at `/data/cache/partmgr-tpm-native-6`. Its manifest records both
`nativeToolUnseal=true` and `externalEngineCommandPassed=true`, with source state
unchanged and the owned emulator shut down. The preserved source-state SHA-256 is
`e94b926671184233e6b8524b6288d65c81073199b3e5060ff045654c48a80450`; measured-log
SHA-256 is `d534a0e445d8fcbd67ebfad4d8ae623d06e137dbd5e0f6c76f0ea5dc2aa72a10`.

Final host validation: formatting and all-target/all-feature Clippy with warnings
denied passed; the full locked all-feature suite passed 761 tests with 88 ignored.
The synthetic full-chain and native cold-PCR/positive-replay gates were invoked
separately. Portable `--no-default-features --features bitlocker` and the
all-feature `x86_64-pc-windows-msvc` compilation checks passed. Cross-compilation
does not supply a Windows TBS transport or establish Windows runtime behavior.
The full test log is `/data/cache/partmgr-tpm-host-tests.log`.
