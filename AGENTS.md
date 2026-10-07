# Repository guidelines

Rust 2024 crate `partmgr`. Strict read-only GPT and MBR partition table parsing (GUID/UEFI support planned).
Published dependencies resolve from crates.io; no sibling checkout is required.
Use `cargo fmt -- --check`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, and `cargo test --all-features --locked`.
Host tests do not establish Windows servicing or capture correctness.
