#!/usr/bin/env python3
"""Emit a source-bound maintenance baseline, never a native qualification receipt.

Run from any directory. Output is JSON on stdout; no source or disk is modified.
Hashes bind exact working-tree bytes, including uncommitted changes. A source
inventory establishes presence only, not implementation correctness or support.
"""

import hashlib
import json
from pathlib import Path
import re


def inventory(root: Path) -> dict:
    """Record deterministic source and evidence hashes without following symlinks."""
    paths = {
        root / "Cargo.toml",
        root / "Cargo.lock",
        root / "src/lib.rs",
        root / "FILESYSTEM_PLAN.md",
    }
    for directory, pattern in (
        ("src", "*.rs"),
        ("tests", "*.rs"),
        ("docs", "filesystem*.md"),
        ("scripts", "filesystem*.py"),
    ):
        paths.update((root / directory).rglob(pattern))
    records = []
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()
        records.append({
            "path": path.relative_to(root).as_posix(),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    lib = (root / "src/lib.rs").read_text()
    # This is a lexical export inventory, not cfg evaluation or API analysis.
    exports = sorted(re.findall(r"^pub mod (fs_\w+);", lib, re.MULTILINE))
    return {
        "schema_version": 1,
        "kind": "maintenance-source-inventory",
        "qualification": "none; hashes establish source identity only",
        "export_scope": "lexical public modules; cfg conditions not evaluated",
        "public_modules": exports,
        "files": records,
    }


if __name__ == "__main__":
    print(json.dumps(inventory(Path(__file__).resolve().parents[1]), indent=2))
