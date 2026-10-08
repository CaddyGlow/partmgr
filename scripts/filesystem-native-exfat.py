#!/usr/bin/env python3
"""Validate bounded exFAT boot inspection against exfatprogs; retain exact evidence."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipt = {"schema": 1, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "scope": "boot regions and geometry only; no namespace/allocation/write/firmware claim",
               "commands": [], "profiles": [], "passed": False}
    sources = [ROOT / p for p in ["src/fs_exfat.rs", "tests/fs_exfat.rs",
               "examples/filesystem-exfat-inspect.rs", "scripts/filesystem-native-exfat.py",
               "Cargo.toml", "Cargo.lock"]]
    receipt["source_sha256"] = {str(p.relative_to(ROOT)): digest(p) for p in sources}

    def save():
        (output / "evidence.json").write_text(json.dumps(receipt, indent=2) + "\n")

    def run(command, expected=0):
        result = subprocess.run([str(x) for x in command], cwd=ROOT, capture_output=True, text=True)
        receipt["commands"].append({"argv": [str(x) for x in command], "exit": result.returncode,
                                    "stdout": result.stdout, "stderr": result.stderr})
        save()
        if (expected == 0 and result.returncode != 0) or (expected != 0 and result.returncode == 0):
            raise RuntimeError(f"unexpected command result: {command}")
        return result.stdout

    try:
        tools = {}
        for name in ["mkfs.exfat", "fsck.exfat", "cargo", "rustc"]:
            path = shutil.which(name)
            if path is None:
                raise RuntimeError(f"required tool missing: {name}")
            tools[name] = {"path": path, "sha256": digest(Path(path))}
        receipt["tools"] = tools
        for name in ["mkfs.exfat", "fsck.exfat"]:
            # exfatprogs -V also displays usage and may return a nonzero status.
            result = subprocess.run([tools[name]["path"], "-V"], capture_output=True, text=True)
            tools[name]["version"] = {"exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        run(["rustc", "--version"])
        run(["cargo", "build", "--locked", "--target-dir", args.target_dir,
             "--example", "filesystem-exfat-inspect"])
        binary = args.target_dir.resolve() / "debug/examples/filesystem-exfat-inspect"
        receipt["binary_sha256"] = digest(binary)
        length = 64 * 1024 * 1024
        for sector in [512, 1024, 2048, 4096]:
            image = output / f"sector-{sector}.img"
            with image.open("wb") as stream:
                stream.truncate(length)
            run([tools["mkfs.exfat"]["path"], "--no-discard", "--sector-size", sector, image])
            before = digest(image)
            run([tools["fsck.exfat"]["path"], "-n", image])
            if digest(image) != before:
                raise RuntimeError("native no-repair check changed image")
            result = run([binary, image, 0, length])
            if f"sector={sector}" not in result or "boot_regions=validated" not in result:
                raise RuntimeError("geometry result mismatch")
            wrapped = output / f"sector-{sector}-bounded.img"
            with wrapped.open("wb") as destination, image.open("rb") as source:
                destination.write(b"\xa5" * 8192)
                shutil.copyfileobj(source, destination, 1024 * 1024)
                destination.write(b"\x5a" * 333)
            wrapper_before = digest(wrapped)
            run([binary, wrapped, 8192, length])
            if digest(wrapped) != wrapper_before or digest(image) != before:
                raise RuntimeError("inspection changed source")
            # Corrupt backup checksum on disposable wrapper; validation must reject.
            at = 8192 + 23 * sector
            with wrapped.open("r+b") as stream:
                stream.seek(at)
                original = stream.read(1)
                stream.seek(at)
                stream.write(bytes([original[0] ^ 1]))
            corrupt_before = digest(wrapped)
            run([binary, wrapped, 8192, length], expected=1)
            if digest(wrapped) != corrupt_before:
                raise RuntimeError("failed inspection changed source")
            receipt["profiles"].append({"sector_bytes": sector, "volume_bytes": length,
                "source_sha256": before, "bounded_source_sha256": wrapper_before,
                "corrupt_source_sha256": corrupt_before, "nonzero_offset": 8192, "passed": True})
            save()
        current = {str(p.relative_to(ROOT)): digest(p) for p in sources}
        if current != receipt["source_sha256"]:
            raise RuntimeError("implementation changed during evidence run")
        receipt["passed"] = True
    except Exception as error:
        receipt["failure"] = str(error)
        raise
    finally:
        save()
    print(output / "evidence.json")


if __name__ == "__main__":
    main()
