# exFAT inspection progress

`fs_exfat::ExfatBoot::inspect` validates revision 1.00 main and backup boot
regions through a bounded immutable `virtdisk::ReadAt`. It checks identifiers,
extended signatures, both checksum sectors and layout arithmetic. Geometry must
agree; backup status fields are treated as stale. Main dirty/media-failure flags
are exposed without clearing them. The parser accepts declared 512–4096-byte
sectors, checks source bounds and charges 8192 bytes of scratch to shared Resources.
Cancellation, I/O causes and changed source length produce explicit errors.

This is boot inspection, not an operational exFAT file reader. Allocation bitmaps,
upcase tables, directory sets/checksums, valid-data-length semantics, file chains,
tree sources, builders and recovery remain required by FILESYSTEM_PLAN.md. Two
FATs are recognized as a TexFAT layout, without transaction support. Boot metadata
does not prove volume consistency or authorize mutation.

The field/checksum reference is Microsoft's
[exFAT specification, revision 1.00, sections 2–3](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification),
inspected 2026-10-07. Independently assembled unit fixtures cover all four sector
sizes, excluded checksum status fields, stale backup status, malformed geometry,
checksum corruption, bounded work, budget exhaustion and injected I/O errors.

`scripts/filesystem-native-exfat.py` generates four independent exfatprogs
fixtures, requires `fsck.exfat -n` acceptance without byte changes, checks direct
and nonzero bounded-region inspection, and requires rejection of a corrupted
backup checksum. Missing tools fail explicitly. It retains commands, versions,
executable/source/image hashes and failure status; no native pass is implied by
the script's existence.

```sh
python3 scripts/filesystem-native-exfat.py \
  --target-dir /data/cache/partmgr-filesystem-target \
  --output /data/cache/partmgr-exfat-boot-new-run
```

Verified exfatprogs 1.3.2 run:
`/data/cache/partmgr-exfat-boot-20261007-b/evidence.json`. All four sector profiles
passed native nonrepair checks, direct/bounded inspection and corruption rejection.
The receipt binds the exact tested implementation and tool hashes.
