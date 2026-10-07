# Repository guidelines

Rust 2024 crate `partmgr`. Strict read-only GPT and MBR partition table parsing (GUID/UEFI support planned).
Sibling checkouts required for path dependencies: `virtdisk`.
Use `cargo fmt -- --check`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, and `cargo test --all-features --locked`.
Host tests do not establish Windows servicing or capture correctness.
