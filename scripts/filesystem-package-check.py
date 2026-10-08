#!/usr/bin/env python3
"""Verify packaged host tests using registry dependencies and retained evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
out = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="partmgr-package-gate-", dir="/data/cache"))
if args.output:
    out.mkdir(parents=True, exist_ok=False)
manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
package = manifest["package"]
base = f'{package["name"]}-{package["version"]}'
receipt = {"scope": "self-contained packaged host tests; no publication, portable target, native filesystem or firmware claim", "commands": [], "status": "failed"}
env = dict(os.environ, RUSTC_WRAPPER="")

def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def run(command, label, cwd):
    started = time.monotonic()
    result = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    log = out / f"{label}.log"
    log.write_bytes(result.stdout)
    receipt["commands"].append({"argv": command, "cwd": str(cwd), "exit_code": result.returncode, "elapsed_seconds": time.monotonic() - started, "log": str(log), "log_sha256": sha(log)})
    if result.returncode:
        raise RuntimeError(f"{label} failed: {log}")
    return result.stdout

try:
    receipt["script_sha256"] = sha(Path(__file__).resolve())
    receipt["rustc"] = run(["rustc", "--version"], "rustc", ROOT).decode().strip()
    receipt["cargo"] = run(["cargo", "--version"], "cargo", ROOT).decode().strip()
    receipt["rustflags"] = env.get("RUSTFLAGS", "")
    run(["cargo", "package", "--allow-dirty", "--no-verify", "--target-dir", str(out / "build")], "package", ROOT)
    artifact = out / "package.crate"
    shutil.copyfile(out / "build/package" / f"{base}.crate", artifact)
    receipt["package_sha256"] = sha(artifact)
    with tarfile.open(artifact) as archive:
        archive.extractall(out / "extracted", filter="data")
    extracted = out / "extracted" / base
    normalized = tomllib.loads((extracted / "Cargo.toml").read_text())
    for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
        for name, dependency in normalized.get(section, {}).items():
            if isinstance(dependency, dict) and ("path" in dependency or "git" in dependency):
                raise RuntimeError(f"non-registry packaged dependency: {section}.{name}")
    receipt["packaged_source_sha256"] = {str(p.relative_to(extracted)): sha(p) for p in sorted(extracted.rglob("*")) if p.is_file()}
    lock = tomllib.loads((extracted / "Cargo.lock").read_text())
    receipt["registry_packages"] = [{k: p[k] for k in ["name", "version", "source", "checksum"] if k in p} for p in lock["package"] if "source" in p]
    for command, label in [
        (["cargo", "fmt", "--manifest-path", str(extracted / "Cargo.toml"), "--", "--check"], "fmt"),
        (["cargo", "clippy", "--manifest-path", str(extracted / "Cargo.toml"), "--all-targets", "--all-features", "--locked", "--target-dir", str(out / "build"), "--", "-D", "warnings"], "clippy"),
        (["cargo", "test", "--manifest-path", str(extracted / "Cargo.toml"), "--all-features", "--locked", "--target-dir", str(out / "build")], "tests"),
    ]:
        run(command, label, extracted)
    receipt["test_binary_sha256"] = {str(p.relative_to(out)): sha(p) for p in sorted((out / "build/debug/deps").glob("*")) if p.is_file() and os.access(p, os.X_OK) and p.suffix == ""}
    receipt["status"] = "passed"
except (OSError, subprocess.SubprocessError, RuntimeError, tarfile.TarError) as error:
    receipt["error"] = str(error)
finally:
    with (out / "evidence.json").open("w") as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    print(f'{receipt["status"].upper()}: {out / "evidence.json"}', flush=True)
raise SystemExit(0 if receipt["status"] == "passed" else 1)
