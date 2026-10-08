#!/usr/bin/env python3
"""Retain independent raw-to-QCOW2 conversion and complete logical-byte evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-bytes", type=int, default=4 << 30)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    if not source.is_file() or not 0 < source.stat().st_size <= args.max_bytes:
        parser.error("source must be a nonempty regular raw image within --max-bytes")
    executable = shutil.which("qemu-img")
    if executable is None:
        parser.error("independent conversion requires qemu-img")
    tool = Path(executable).resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipt = {
        "status": "failed", "commands": [], "source": str(source),
        "source_bytes": source.stat().st_size, "source_sha256": digest(source),
        "tool": str(tool), "tool_sha256": digest(tool),
        "script_sha256": digest(Path(__file__).resolve()),
        "scope": "independent conversion and complete logical-byte equality; caller must keep source stable; no filesystem, publication or firmware claim",
    }

    def run(label, arguments):
        command = [str(tool), *arguments]
        result = subprocess.run(command, capture_output=True, timeout=600)
        stdout = output / (label + ".stdout")
        stderr = output / (label + ".stderr")
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        receipt["commands"].append({
            "argv": command, "exit_code": result.returncode,
            "stdout": stdout.name, "stdout_sha256": digest(stdout),
            "stderr": stderr.name, "stderr_sha256": digest(stderr),
        })
        if result.returncode:
            raise RuntimeError(f"{label} failed; retained stdout/stderr")
        return result.stdout

    try:
        run("version", ["--version"])
        receipt["images"] = {}
        for profile, options in [("normal", []), ("compressed", ["-c"])]:
            image = output / (profile + ".qcow2")
            restored = output / (profile + ".raw")
            run(profile + "-convert", ["convert", "-f", "raw", "-O", "qcow2", *options, str(source), str(image)])
            info = json.loads(run(profile + "-info", ["info", "--output=json", "-f", "qcow2", str(image)]))
            if info["virtual-size"] != receipt["source_bytes"] or "backing-filename" in info:
                raise RuntimeError("conversion changed logical geometry or added a backing dependency")
            run(profile + "-check", ["check", "-f", "qcow2", str(image)])
            run(profile + "-compare", ["compare", "-f", "raw", "-F", "qcow2", str(source), str(image)])
            run(profile + "-restore", ["convert", "-f", "qcow2", "-O", "raw", str(image), str(restored)])
            if restored.stat().st_size != receipt["source_bytes"] or digest(restored) != receipt["source_sha256"]:
                raise RuntimeError("complete restored logical image differs")
            receipt["images"][profile] = {"qcow2_sha256": digest(image), "restored_sha256": digest(restored)}
        receipt["source_sha256_end"] = digest(source)
        receipt["tool_sha256_end"] = digest(tool)
        if receipt["source_sha256_end"] != receipt["source_sha256"] or receipt["tool_sha256_end"] != receipt["tool_sha256"]:
            raise RuntimeError("source or tool changed during verification")
        receipt["status"] = "passed"
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        receipt["error"] = str(error)
    finally:
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"{receipt['status']}: {output / 'receipt.json'}")
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
