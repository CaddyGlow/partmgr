# Repository guidelines

Rust 2024 crate `partmgr`. Lossless GPT/MBR inspection, owned editing, explicit durable commits, recovery, UEFI integration, and independent payload operations.
Published dependencies resolve from crates.io; no sibling checkout is required.
Use `cargo fmt -- --check`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, and `cargo test --all-features --locked`.
Host tests do not establish Windows servicing, capture correctness, or firmware boot correctness. Firmware evidence belongs to the separate QEMU/OVMF integration gate.
