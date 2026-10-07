# partmgr

Strict read-only GPT and MBR partition table parsing (GUID/UEFI support planned).

```toml
partmgr = "0.1.0"
```

```sh
cargo test --all-features --locked
```

For source builds, clone `virtdisk` beside this repository. CI checks formatting, Clippy and tests on Linux and Windows. A matching `v0.1.0` tag runs validation, verifies and publishes the crate, then creates its GitHub Release with checksums.
