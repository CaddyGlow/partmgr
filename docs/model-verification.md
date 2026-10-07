# Owned model and EBR verification

These tests establish table-model behavior. They do not establish firmware boot,
Windows servicing, filesystem correctness, or dynamic-volume support.

| Requirement | Authoritative behavioral tests |
| --- | --- |
| Borrowed readers, owned models, bounded partition views | `borrowed_view_is_bounded`, `owned_raw_metadata` |
| Independently constructed 512/4096 GPT metadata | `owned_raw_metadata` |
| Inclusive/exclusive range conversion, checked overflow | `checked_ranges`, `exhaustive_small_alignment_and_checked_range_properties` |
| Metadata-bounded reads on sparse large geometry | `sparse_large_geometry_uses_bounded_metadata_reads` uses sparse overlays representing large disks and asserts fewer than 65536 metadata bytes read |
| GPT CRC and semantic validation | `rejects_crc_bounds_and_inconsistent_copies`, `semantic_invalidity_after_valid_checksums` |
| Exact UTF-16 units, unused slot bytes, extended entry bytes | `owned_raw_metadata`, `opaque_unused_slots_and_dynamic_types_survive_inspection`, `extended_entries_are_lossless_and_header_extensions_refuse_mutation` |
| Unsupported semantics separated from raw preservation | `extended_entries_are_lossless_and_header_extensions_refuse_mutation`, `reserved_attributes_raw_inspection_and_new_slot_prefix` |
| MBR signature, boot flags/code, CHS, logical-sector remainder | `basic_mbr_preserves_independent_boot_chs_signature_and_tail` independently constructs both sector sizes and checks preservation across edits |
| Pure transactional edits, IDs, slot selection, alignment | `failed_edits_are_transactional`, `initialize_place_and_preserve_mbr_sector`, `exhaustive_small_alignment_and_checked_range_properties` |
| Dynamic entries recognized without standalone-volume or mutation support | `opaque_unused_slots_and_dynamic_types_survive_inspection`, `basic_mbr_preserves_independent_boot_chs_signature_and_tail` |
| EBR-relative data and container-relative link addressing | `relative_bases_and_cycle` |
| EBR cycles, chain limits, bounds, metadata/payload overlap | `chain_limits_and_metadata_overlaps_are_rejected`, `relative_bases_and_cycle`, `new_ebr_cannot_overwrite_deleted_source_payload` |
| EBR 4096-sector preservation and readback | `independently_built_4096_chain_preserves_sector_tail` |
| EBR create/delete, empty container, first-entry relocation, CHS/boot preservation | `transactional_edit_topology_commit_and_payload_preservation`, `empty_chain_and_first_delete_preserve_boot_code_and_link_chs` |
| Incoming link length, unchanged link bytes, nonmonotonic chain locations, placement | `link_lengths_out_of_order_topology_and_aligned_placement` |
| EBR interruption outcome and explicit rollback | `every_ebr_short_write_and_flush_boundary_can_restore_selected_snapshot` injects failures at all 1539 one-byte-write/flush boundaries for three stages, observes valid or invalid intermediate tables, then restores the explicitly selected retained original metadata snapshot and verifies payload preservation |

The EBR rollback test retains the original owned layout separately from storage.
This is essential: EBR tables have no metadata redundancy, partial writes can
invalidate entries, and write ordering does not make publication atomic. Callers
must retain a trusted metadata snapshot outside overwritten sectors if rollback
is required. Recovery does not silently select damaged on-disk bytes.

Required repository checks have passed during integration:

```sh
cargo fmt -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

`cargo check --all-targets --all-features --locked --target
x86_64-pc-windows-msvc` also passed. This is Windows compilation evidence;
Windows runtime tests require the separate Windows CI or guest run. External-tool
and firmware integration evidence belongs to the repository-wide verification
record, not to these model tests.
