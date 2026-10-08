# Observed FAT firmware execution

`scripts/firmware-gate.py` independently observes execution of a generated minimal x86-64 EFI application under QEMU/OVMF. Its default `--fat-source native` preserves the existing path: dosfstools formats a 96 MiB FAT32 image and mtools installs the application at `EFI/BOOT/BOOTX64.EFI`.

`--fat-source framework` builds `filesystem-fat-build-tree` and gives it the actual generated EFI application's bytes. The framework emits its deterministic nested FAT32 image, including the fallback application and additional fixture files, using the existing forward-order tree profile. This mode uses a 64 MiB declared filesystem inside a 96 MiB ESP; the remaining 32 MiB partition tail stays zero. Both modes require an independent `fsck.fat -n -v` exit zero and an unchanged prepared FAT hash before creating firmware disk images.

For either source, the gate builds representative GPT and MBR disks through the `firmware-image` example, checks their table metadata through `sfdisk --json`, and requires the declared ESP to begin at sector 2048 and span 196608 sectors with the appropriate GPT ESP GUID or MBR type EF. It copies the prepared filesystem into that partition and flushes the disk image. A separate writable copy of the OVMF variable template is used for each guest.

QEMU runs with q35, TCG, no display and no host monitor. The generated EFI application writes `PARTMGR_FIRMWARE_OK` through the guest debug port and requests exit through `isa-debug-exit`. A profile passes only when both GPT and MBR guests emit the exact marker and QEMU exits 33. A FAT parser test or successful fsck alone cannot satisfy this firmware gate. The EFI payload is a small generated test application, not an arbitrary OS loader.

Run the framework profile with a matching OVMF code and variable template:

```sh
python3 scripts/firmware-gate.py \
  --fat-source framework \
  --ovmf-code /path/to/OVMF_CODE.fd \
  --ovmf-vars /path/to/OVMF_VARS.fd \
  --target-dir /data/cache/partmgr-framework-firmware-target \
  --output /data/cache/partmgr-framework-firmware-new-run
```

The output directory must not already exist. `--target-dir` is optional and otherwise respects `CARGO_TARGET_DIR` or Cargo's usual local target directory. Missing tools or firmware fail explicitly. A failed command or guest timeout leaves a failed receipt and retained logs; it never becomes a skipped pass.

Schema-two `receipt.json` records the native/framework FAT origin and profile, OVMF code and variable-template hashes, generated application hash, prepared FAT hash and dimensions, script/manifests/Rust source hashes, built example hashes, tool paths and hashes with version output, every command and exit status with hashed logs, independently parsed tables, guest debug-log hashes, QEMU commands and per-scheme exit/marker status. Disk and variable-file hashes after boot are recorded separately; the guest has writable copies and the gate makes no claim that its boot phase is read-only. Implementation source hashes before and after the gate must match so edits during a run require another run.

`.github/workflows/firmware.yml` runs separate native and framework matrix jobs and retains each profile's artifact independently. This keeps the external native-FAT boot evidence distinguishable from boot evidence for the framework-authored FAT.

This gate establishes observed fallback execution of this exact generated x86-64 application on the representative GPT and MBR ESP layouts. It does not establish Secure Boot, arbitrary bootloaders, Windows servicing, system installation, capture correctness, power-loss recovery, or firmware behavior on other machines. Filesystem, partition-table and runtime firmware evidence remain separate layers.

Verified framework run: `/data/cache/partmgr-framework-firmware-20261007-b/receipt.json`. Verified native-default regression run: `/data/cache/partmgr-native-firmware-20261007-b/receipt.json`. Both observed the generated application marker and QEMU exit 33 separately on GPT and MBR guests using OVMF 202608 and the recorded local QEMU executable. The receipts record the exact tested source, binary, application, filesystem and firmware hashes; later changes need new evidence.
