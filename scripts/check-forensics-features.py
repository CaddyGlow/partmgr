#!/usr/bin/env python3
"""Prove public API exclusion/inclusion by compiling a separate consumer.

Run under the repository's Rust development shell. Shared Cargo configuration is
inherited. The supplied evidence directory must not already exist.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    repository = Path(__file__).resolve().parents[1]
    consumer = root / "consumer"
    (consumer / "src").mkdir(parents=True)
    (consumer / "src/lib.rs").write_text("use partmgr::forensics::ScanLimits;\npub fn ceilings() -> ScanLimits { ScanLimits::default() }\n")
    rows = []
    for name, defaults, features, expected in [
        ("default-excludes", True, [], False),
        ("portable-excludes", False, [], False),
        ("portable-includes", False, ["forensics"], True),
        ("std-includes", True, ["forensics"], True),
    ]:
        manifest = '[package]\nname="partmgr-forensic-feature-consumer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\npartmgr={path=' + json.dumps(str(repository)) + ',default-features=' + str(defaults).lower() + ',features=' + json.dumps(features) + '}\n'
        (consumer / "Cargo.toml").write_text(manifest)
        command = ["cargo", "check", "--offline", "--manifest-path", str(consumer / "Cargo.toml")]
        result = subprocess.run(command, capture_output=True)
        (root / (name + ".stdout")).write_bytes(result.stdout)
        (root / (name + ".stderr")).write_bytes(result.stderr)
        stderr = result.stderr.decode(errors="replace")
        passed = result.returncode == 0 if expected else result.returncode != 0 and "could not find `forensics` in `partmgr`" in stderr
        rows.append({"name": name, "command": command, "exit_code": result.returncode,
                     "manifest": manifest, "expected_api_available": expected,
                     "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(), "passed": passed})
    receipt = {"version": 1, "profile": "compiled-consumer-api-feature-matrix",
               "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "cargo_toml_sha256": hashlib.sha256((repository / "Cargo.toml").read_bytes()).hexdigest(),
               "lib_rs_sha256": hashlib.sha256((repository / "src/lib.rs").read_bytes()).hexdigest(),
               "checks": rows, "passed": all(row["passed"] for row in rows)}
    (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(root / "receipt.json")}))
    raise SystemExit(0 if receipt["passed"] else 1)


if __name__ == "__main__":
    main()
