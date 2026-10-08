#!/usr/bin/env python3
"""Validate QCOW2 conversions of a retained native partition-copy checkpoint."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    native_path = args.receipt.resolve(strict=True)
    native_bytes = native_path.read_bytes()
    native_hash = hashlib.sha256(native_bytes).hexdigest()
    native = json.loads(native_bytes)
    if native.get("status") != "passed" or not native.get("images"):
        parser.error("a successful native partition-copy receipt is required")
    converter = Path(__file__).resolve().with_name("filesystem-container-check.py")
    # Verify all retained raw disks before creating any conversion artifacts.
    inputs = {}
    for name, record in native["images"].items():
        if not isinstance(name, str) or name in [".", ".."] or Path(name).name != name:
            parser.error("image labels must be single path components")
        image = native_path.parent / (name + ".img")
        if digest(image) != record["disk_sha256"]:
            parser.error("retained raw disk differs: " + name)
        inputs[name] = image
    if digest(native_path) != native_hash:
        parser.error("native receipt changed during input preflight")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {
        "status": "running", "native_receipt": str(native_path),
        "native_receipt_sha256": native_hash,
        "script_sha256": digest(Path(__file__).resolve()),
        "converter_sha256": digest(converter), "images": {},
        "scope": "independent normal/compressed QCOW2 conversion and complete logical-disk equality for retained native partition copies; no filesystem editor, firmware or timing acceptance",
    }
    try:
        for name, image in inputs.items():
            destination = output / name
            command = [sys.executable, str(converter), str(image), "--output", str(destination)]
            child = subprocess.run(command, capture_output=True, timeout=1800)
            stdout = output / (name + ".stdout")
            stderr = output / (name + ".stderr")
            stdout.write_bytes(child.stdout)
            stderr.write_bytes(child.stderr)
            record = {"argv": command, "exit_code": child.returncode,
                      "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)}
            result["images"][name] = record
            if child.returncode:
                raise RuntimeError(name + ": converter failed; logs retained")
            child_receipt = destination / "receipt.json"
            converted = json.loads(child_receipt.read_text())
            expected = native["images"][name]["disk_sha256"]
            if (converted["status"] != "passed"
                    or converted["source_sha256"] != expected
                    or converted["source_sha256_end"] != expected):
                raise RuntimeError(name + ": conversion receipt differs")
            record.update(receipt=str(child_receipt), receipt_sha256=digest(child_receipt),
                          disk_sha256=expected, native_profile=native["images"][name])
            print(name + ": passed", flush=True)
        for name, image in inputs.items():
            if digest(image) != native["images"][name]["disk_sha256"]:
                raise RuntimeError(name + ": input changed")
        if (digest(native_path) != result["native_receipt_sha256"]
                or digest(converter) != result["converter_sha256"]
                or digest(Path(__file__).resolve()) != result["script_sha256"]):
            raise RuntimeError("source receipt or gate changed")
        result["status"] = "passed"
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result.update(status="failed", error=str(error))
    finally:
        (output / "receipt.json").write_text(json.dumps(result, indent=2) + "\n")
    print(str(output / "receipt.json"), flush=True)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
