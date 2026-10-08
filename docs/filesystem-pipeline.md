# Pipeline outcomes

`fs_pipeline::PipelineReport` records source, container, partition, filesystem,
copy, boot and publication outcomes independently. Its public contract is
version1. An unattempted layer stays `NotAttempted`; a caller explicitly marks
an inapplicable layer with its reason. Table validity does not imply filesystem
validity or boot success.

Completed operations distinguish validation, accepted mutation, confirmed
durability and visible publication. `observe` returns the original typed result
while recording the caller-declared assurance or failure state and recovery
action. Callers must observe actual barriers and verification before recording
`Durable`. Reports do not run operations or make several commits atomic.

The FAT, exFAT, ext and APFS copy examples emit a report on success and failure.
They share the no-clobber publication and directory-barrier implementation.
Each inventories the
source, preflights the explicit content-only metadata policy, emits and verifies
unpublished filesystem bytes, commits and inspects any table, reopens a complete
allocation audit, then publishes without replacing an existing destination.
Failures before publication identify disposable staging. Publication errors may
leave an artifact visible and require inspection. A failed parent-directory open
or flush after publication records `PublishedDurabilityUncertain` with
`InspectPublishedArtifact`; it never says the published image was discarded.
Boot remains unattempted.

The frozen copy checkpoint at
`/data/cache/partmgr-copy-pipeline-native-v2-4spfac13/root-audit.json`
binds ten GPT/MBR profiles, thirty complete native payload models, twenty
existing-destination/invalid-table controls and sixteen publication controls
across the four frontends. Directory-flush fault injection leaves visible
output byte-identical to the successful counterpart while returning the original
I/O cause and reporting uncertain publication durability. Its source snapshot
passes formatting, strict Clippy and the full host suite (453 passed, 40 ignored).
This checkpoint excludes subsequent engine drafts and proves no firmware boot
or cross-layer atomicity.

The textual representation prints one escaped record per layer. Native names
and error descriptions retain their text without introducing extra records.
Use the typed API for decisions; the text is a diagnostic representation rather
than JSON. A report summarizes the current layer outcomes, not a transaction
journal or a source of recovery authority. Filesystem anchors, journals and
container recovery evidence remain owned by their respective protocols.
