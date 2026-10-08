# External filesystem undo protocol v1

`fs_undo` provides bounded exact before/after patches and an external persistent
undo record. It is the recovery foundation for future filesystem editors, not an
allocation audit, a filesystem journal, or permission to edit an arbitrary image.
A format engine must validate and maintain its own ownership, namespace, dirty
state and native invariants before constructing a plan.

The caller holds exclusive access to the target and recovery medium throughout
commit or recovery. They must be disjoint and independently durable; a recovery
file inside the filesystem being edited does not meet this contract. Rust mutable
borrows and a backend advisory lock do not exclude external mounted writers.
Neither medium is exposed as immutable `ReadAt` while it can change. Use bounded
sessions to bind target offsets to the selected region. The supplied volume key
must identify that actual volume and region; recovery compares the explicit
volume key, session generation, transaction ID and target length before writes.
The protocol cannot authenticate a caller-supplied key or detect arbitrary
aliasing hidden behind two `Storage` implementations.

Planning accepts sorted, nonoverlapping equal-length `WriteRange` patches. It
checks every range and encoded size, bounds patch count/body size, and charges
the retained vector capacities rather than assuming capacity equals length.
All expected target bytes are compared before journal mutation. The operation
saves only affected bytes, with constant 64 KiB verification scratch; an ordinary
range edit does not snapshot or rewrite the complete target. Cancellation and
short writes are checked throughout. No per-buffer target flush is introduced.

Commit barriers are:

1. Refuse a pending prepared transaction. Clear reusable terminal headers and
   flush the journal. A partially cleared unpublished journal can require an
   explicit new recovery medium, while the target remains unchanged.
2. Save the complete bounded old/new patch body, flush it and verify readback.
3. Publish and flush the integrity-checked prepared header, then verify it.
4. Apply target replacements, flush the target once and verify every replacement.
5. Publish, flush and verify the committed header in the second header slot.

There are two 512-byte header slots; body records begin at byte 1024. Integers are
little-endian. Each patch stores an offset and length followed by exact old and
new bytes. Headers bind version, state, volume/session/transaction identity,
target length, body length, patch count and SHA256 of the full body. Header SHA256
covers its first 480 bytes; the final 32 bytes hold the digest. Reserved fields
must be zero. A valid terminal header must agree with an intact prepared header
on every binding/body field. No sector-atomic-write assumption is made: an
interrupted header is accepted only if its full integrity check succeeds.
SHA256 is accidental-corruption detection, not adversarial authentication.

Recovery verifies all body bytes, all patch boundaries and the complete binding
before its first target write. A prepared record restores all saved bytes,
flushes and verifies them, then publishes a rolled-back terminal marker. An
interrupted rollback leaves the prepared header intact and can restart from the
beginning. Committed or rolled-back records are verified against the target and
produce no target writes. A mismatched terminal target is an error, not authority
to overwrite it. An intact terminal record wins over its prepared predecessor;
an incomplete terminal write falls back to the prepared rollback obligation.

`UndoFailure` identifies the failing stage, whether a prepared transaction may
need recovery and whether target writes were attempted. Marker flush failures
can leave either a valid terminal record or its prepared predecessor after a
restart; inspect the actual journal rather than infer state from the error.
Never retry an edit over a prepared transaction. Restore/audit the volume under
the exclusive session before opening new immutable reader handles or publishing
success. Journal retirement or filesystem recovery cannot make partition,
container, publication-directory or boot stages atomic together.

Four portable tests cover every modeled commit write/barrier cut and every
rollback write/barrier cut, torn writes, both retained/lost unflushed bytes,
positive short writes, stale targets, geometry/overlap rejection, pending
transactions, corrupted bodies, wrong bindings, bounded recovery, cancellation,
terminal mismatch and retained-capacity refunds. These are explicit persistence
models, not physical-device power-loss evidence. Native consumers must separately
reopen and validate their filesystem profile; see `filesystem-undo-native.md`.

## Ordered target stages

`UndoPlan::new_staged` accepts the same disjoint bounded patches plus nonempty
stage lengths describing the input order. Their checked sum must cover every
patch exactly once; stage count is bounded by patch count. A leased index retains
that order while the saved v1 body remains physically sorted. No stage metadata
is added to the journal, and the recovery parser is unchanged.

The complete undo body and Prepared marker are durable and verified before any
target stage. Each stage writes its replacements, flushes the target and verifies
those ranges before the next stage begins. All replacements are checked again
before publishing Committed. A file-allocation planner can therefore initialize
new data in the first stage and publish references in the next. This ordering
is a caller-selected protocol; the generic undo engine does not prove which
patches contain data or metadata. The unstaged `new` path retains its existing
single target flush behavior.

New portable tests assert initialized data is durable before lower-addressed
metadata writes, reject stage-readback failure before metadata is touched,
exercise every staged write/barrier cut with retained/lost unflushed bytes,
verify full rollback and idempotent terminal recovery, reject invalid stage
coverage/overflow and refund reservations. Successful staged and unstaged
transactions produce byte-identical v1 journals for the same binding and
patches. This modeled evidence does not establish physical power-loss behavior;
filesystem consumers must add their native operation gates.

## Engine-specific recovery preflight

An internal read-only validator can require native fence patches after complete
saved-body digest, patch decoding, sorted-range/bounds and trailing-byte checks.
Every range callback and final semantic check finishes before any restoration
write. The public recovery API uses a no-op validator and retains the same v1
wire format and behavior. This lets ext2 locate its clean-state patch after
sorted free-counter patches without duplicating or guessing journal framing.
Two unit invariants cover a rejected/cancelled fence without target/journal
mutation and a rehashed malformed later range that never reaches callbacks.
Eight existing undo tests still pass. Actual ext2 dirty fencing and clean-last
recovery require that engine's independent protocol and evidence gates.
