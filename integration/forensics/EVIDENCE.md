# Forensic qualification evidence

The full [forensics plan](../../docs/filesystem-forensics-plan.md) is not qualified.
Unit/in-memory and regular-file tests do not establish native device behavior.

## Linux physical adapter attempt, 2026-10-13

Attempted upstream command from the sibling `virtdisk` working directory:

```sh
nix develop --no-write-lock-file path:/home/rick/projects-caddy/nix-dev-shells/rust-xwin -c bash scripts/test-physical-disk.sh
```

The command exited with status 1 before device provisioning:

```text
sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
sudo: a password is required
```

This was an unsuccessful host provisioning attempt. The later disposable-guest
runs below supersede it for their explicitly tested profiles.

## Passing native device profiles, 2026-10-13

- [Linux receipt](linux-native-20261013.json): Debian kernel 6.12.107, upstream
  physical adapter test plus partmgr raw/native partition and FAT equivalence at
  both 512-byte and 4096-byte logical sectors. All four selected tests ran and
  passed; fixture hashes remained unchanged.
- [Windows adapter receipt](windows-native-adapter-20261013.json): Windows build
  26200, upstream physical reads/bounds/concurrency on a newly created read-only
  fixed VHD with 512-byte logical sectors. The first attempt lacked the MSVC
  runtime and is retained [separately](windows-runtime-missing-20261013.json).
  A signature-verified Microsoft runtime was installed only in the disposable guest.
- [Windows partmgr receipt](windows-partmgr-native-20261013.json): raw/native
  partition/FAT equivalence with explicit device write-protection proof. The
  Storage provider could not expose this FAT fixture through `MSFT_Disk`; the
  runner records that condition and resolves only its owned image's device path,
  querying geometry and write protection with metadata-only native IOCTLs.
  Raw, fixed-VHD-container and native-logical-disk hashes are separate and stable.

These receipts bind the executed test binaries by SHA256. They do not qualify a
published release, hot removal, general media changes or firmware boot. The
development path dependency still needs a published upstream API and fresh
qualification against that consumed release.

## FAT native tooling comparison, 2026-10-13

[The comparison receipt](fat-tool-oracle-20261013.json) covers native FAT12
formatting, long-name deletion and subsequent allocation reuse using dosfstools
and mtools. Partmgr's live extraction matches Sleuth Kit `icat` and the original
known content exactly on both closed fixtures. Raw deleted aliases and LFN
fragments remain distinguishable, and fixture hashes before/after inspection match.

The complete binary, runner, fixtures, stdout/stderr (including tool versions),
JSONL/manifests and receipt are retained in
`/data/cache/partmgr-forensics-native-20261013/fat-tool-evidence.tar.gz`, SHA256
`8eae3b00232f783df042c68f544c827c2829cc00232d948b6a3d459e06778ad5`.
This is a selected FAT12 profile comparison; it does not establish every FAT
variant or authenticate recovered historical content.

## Windows NTFS native operations and rollover

[Clean qualification](windows-ntfs-native-20261013.json) and
[dirty/rollover qualification](windows-ntfs-dirty-rollover-native-20261013.json)
retain 37 and 41 checks, respectively. Their paired
[clean creation](windows-ntfs-creation-20261013.json) and
[dirty creation](windows-ntfs-dirty-rollover-creation-20261013.json) receipts
record private Windows-created VHD operations and closed acquisition artifacts.
Checks compare raw volume, disk region and QCOW2 inventories, known native/TSK
live stream hashes (resident, ADS, sparse and LZNT1), independent timestamp sets,
reused/deleted records, USN native fields and retention, and separate LogFile
restart observations. Derived malformed cases retain bad raw fixups, mirror
disagreement and failure before the first observation. The rollover fixture
retains a sparse prefix rather than inventing missing history.

Deleted extraction identifies current acquired bytes. Windows TRIM altered the
deleted fixture; agreement with TSK does not authenticate original content.
These receipts cover their bound binary/source snapshots, not later edits.
The refreshed qualifications include FAT-copy comparison changes and bind all
Rust source files, Cargo manifests/lockfile and the CLI with before/after hashes.
The clean and dirty runs passed all 37 and 41 checks respectively.

## FAT16/FAT32 and mutation smoke

[FAT16](fat16-tool-oracle-20261013.json) and
[FAT32](fat32-tool-oracle-20261013.json) native mtools/TSK comparisons also pass
for closed deleted and reused fixtures with exact live content hashes. Their
complete evidence archive is
`/data/cache/partmgr-forensics-native-20261013/fat-families-tool-evidence.tar.gz`,
SHA256 `89a8f2e0c3ea328890b3cc2e8ff47b8d10f1bc957a465663d9d18f86549d57f3`.

[Deterministic mutation smoke](mutation-smoke-20261013.json) completed 10,000
cases with positive FAT slot/entry, MFT, FILE and USN parser paths and unchanged
source snapshot hashes. It is feedback-free and uninstrumented; it does not
replace an instrumented campaign or establish absence of malformed-input bugs.
The refreshed 10,000-case run includes both FAT-copy comparison APIs and retains
the current source hashes. All cases completed without a retained panic.

[Instrumented smoke](instrumented-smoke-20261013.json) additionally completed
1,001 honggfuzz iterations with zero crashes or timeouts. The cache-local tool
variant preserves Cargo's configured wrapper, output directory and profile;
its patch/tool hashes are retained in the receipt. Native compilation required
binutils development headers and a clean native C build. This receipt excludes
subsequent audit fixes and remains bounded smoke, not security qualification.

[Sorted USN CLI qualification](timeline-usn-cli-20261013.json) verifies native
chronological ticks, exact record/raw/provenance preservation between source-order
and sorted output, structural metadata, terminal outcomes, temporary-file cleanup
and unchanged source hashes on the closed native Windows fixture.

## Remaining receipts

`qualify-release.py --evidence-dir NEW_DIRECTORY`, run inside the development
shell, records the required locked repository checks, feature matrix, compiled
consumer gate and CLI binary hash. It rejects non-registry dependencies in the
lockfile and resolved metadata and requires unchanged source hashes throughout.
This is a host gate; it does not replace the native adapter or firmware gates.
The publication-pending attempt is retained under
`/data/cache/partmgr-forensics-release-publication-pending-20261013`; it did not
pass because the lockfile still contains unpublished dependency entries.

The FAT tooling runner derives a separate malformed-LFN/timestamp/slack fixture
and records exact patches and before/after hashes. The new controls pass for
[FAT12](fat12-negative-prepublication-20261013.json),
[FAT16](fat16-negative-prepublication-20261013.json) and
[FAT32](fat32-negative-prepublication-20261013.json) with native mtools fixtures
and independent TSK live hashes. Each run rejects post-terminator extraction with
no output files and preserves malformed name/timestamp bytes. These runs bind
the previously built CLI by binary hash, not the current publication-transition
sources. They must be repeated against the published-dependency release binary.
Artifacts remain under `/data/cache/partmgr-forensics-fat12-negative-prepublication`
and the corresponding `fat16`/`fat32` directories.

The [compiled consumer feature gate](feature-consumer-20261013.json) proves that
default and no-default builds reject imports of the forensic public API, while
portable and standard-library forensic builds accept them. Its manifests and
compiler diagnostics are retained beside the receipt's evidence directory.
No new forensic-only dependency is activated: `forensics = []`.

- Consumed published-release native adapter runs, hot-removal/fault profiles and
  broader filesystem/backend equivalence.
- Immutable clean/dirty/deleted/reused NTFS and FAT fixture hashes before and
  after inspection, tool and OS versions, and independent inventory/hash comparisons.
- Source-bound malformed-input mutation campaign with budgets, timeouts and
  retained outcomes. The new fuzz harness and seed smoke alone are insufficient.
- Complete CLI interruption/output-failure and chronological export qualification.

Record exact commands, fixture/source hashes, tool versions, backend/OS and full
results beside each future receipt. Keep failed attempts distinct from passes.
