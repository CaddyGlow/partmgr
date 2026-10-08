# Declared logical NOR flash storage

`fs_flash::FlashStorage` is a mutable storage contract, separate from immutable
`virtdisk::ReadAt` and ordinary block replacement. Geometry declares erase-block
and program alignment, erased-byte value, allowed programming transitions and
dump layout. Programming, erasing, readback and durable flush are separate
operations. The contract does not authorize host-device discovery or publication.

`FlashImage<S: Storage>` owns its backing image without mutable aliases. The
caller must retain the backend's actual exclusive/stable-storage contract.
Its initial profile is explicitly declared logical NOR: erased bytes are 0xff,
programming can only clear bits, and the image consists of complete erase blocks.
Non-power-of-two geometries are permitted when program alignment divides erase
alignment; no physical device geometry is guessed. A declared physical NAND
page/OOB layout, other erased values or other transition rules fail Unsupported.
NAND ECC, page-program counts, OOB decoding, bad-block discovery/remapping, wear
and hardware timings require separately implemented profiles and evidence.

The caller supplies sorted unique bad erase-block indices and independent
bad-block, per-operation byte and scratch ceilings. Bad blocks may be read for
inspection but any program/erase crossing one fails before mutation. The entire
program range is read and checked for forbidden zero-to-one transitions before
any write, including violations in the last scratch chunk. There is no implicit
erase. Erase requests must cover complete aligned blocks. All arithmetic and
region crossings are checked before writes. Fixed length is rechecked throughout
operations; stale length, cancellation and causal I/O errors remain explicit.

Scratch, erase buffers and retained bad-block indices are fallibly allocated and
leased against the shared memory pool, including actual capacity checks. Payload
buffers belong to the caller. Reads use caller buffers; erase/program preflight
and verification use bounded scratch rather than a complete image allocation.
Short backend writes are completed and read back. The emulator models interruption
within a logical erase block; it advertises no atomic program, erase or sector
write and does not reproduce an actual chip's interruption behavior.

`FlashProgress` distinguishes accepted from verified bytes. Neither means durable
completion. `FlashFailure` records the operation, known progress, whether mutation
was attempted and the causal domain error. An error can hide extra partial bytes
even when accepted count is zero. Cancellation/readback failures after a write
are InterruptedWrite; flush failure is UncertainDurability. Uncertainty is sticky
after later successful operations or flush. Format-specific recovery may continue
using reads and physically permitted operations; no generic rollback, clean-state
reset, JFFS2 reconstruction, append/GC or recovery guarantee is supplied here.
`into_storage` releases the backend together with the uncertainty flag.

The distinction between NOR operations and physical NAND/OOB follows the pinned
Linux v6.17 [SPI NOR interface](https://www.kernel.org/doc/html/v6.17/driver-api/mtd/spi-nor.html)
and [NAND interface](https://www.kernel.org/doc/html/v6.17/driver-api/mtdnand.html).
Those native drivers do not establish hardware correctness of this image emulator.
The JFFS2 format/specification and native-oracle ledger remains in
[filesystem-specifications.md](filesystem-specifications.md).

Six portable tests cover declared profile/geometry refusal, bad blocks, complete
transition preflight, bounds/overflow/alignment, memory refunds, short writes,
readback, flush versus accepted bytes, stale length, cancellation and causal
errors. Every modeled short-write failure boundary is exercised for 32-byte
programming and 64-byte erasing, preserving all unaffected blocks and the modeled
durable pre-flush image. These are 48 write cuts, not physical power-loss evidence.

```sh
cargo test --locked --test fs_flash
```

JFFS2 reading, offline authoring, CRC/version reconstruction, compression profiles,
append/erase/GC recovery, native mtd-utils/mount validation and physical backends
remain required by FILESYSTEM_PLAN.md.
