#!/usr/bin/env python3
"""Record locked host release checks against published dependencies.

Run inside the repository development shell. Native-device and firmware gates
remain separate. The evidence directory must be new; failures retain their logs.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(repository):
    paths = {repository / "Cargo.toml", repository / "Cargo.lock"}
    for directory, pattern in [("src", "*.rs"), ("tests", "*.rs"),
                               ("examples", "*.rs"), ("scripts", "*.py"),
                               ("integration/forensics", "*.py")]:
        paths.update((repository / directory).rglob(pattern))
    return {str(path.relative_to(repository)): digest(path) for path in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    receipt = {"version": 1, "profile": "published-dependency-locked-host-release",
               "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "scope": "host checks only; native device and firmware receipts required separately",
               "source_sha256_before": snapshot(repository), "commands": [], "passed": False}

    def run(name, argv):
        result = subprocess.run(argv, cwd=repository, capture_output=True)
        for kind, content in [("stdout", result.stdout), ("stderr", result.stderr)]:
            (evidence / f"{name}.{kind}").write_bytes(content)
        receipt["commands"].append({"name": name, "argv": argv,
                                    "exit_code": result.returncode,
                                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                                    "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
        if result.returncode:
            raise RuntimeError(f"{name} failed; retained stdout/stderr")
        if snapshot(repository) != receipt["source_sha256_before"]:
            raise RuntimeError("source changed during qualification")
        return result.stdout

    try:
        lock = tomllib.loads((repository / "Cargo.lock").read_text())
        package = tomllib.loads((repository / "Cargo.toml").read_text())["package"]["name"]
        non_registry = [entry["name"] for entry in lock["package"]
                        if entry["name"] != package and
                        not entry.get("source", "").startswith("registry+")]
        if non_registry:
            raise RuntimeError(f"lockfile contains unpublished dependencies: {non_registry}")
        metadata = json.loads(run("metadata", ["cargo", "metadata", "--locked", "--format-version", "1"]))
        receipt["dependencies"] = [
            {"name": entry["name"], "version": entry["version"], "source": entry["source"]}
            for entry in metadata["packages"] if entry["name"] != package]
        if any(not entry["source"] or not entry["source"].startswith("registry+")
               for entry in receipt["dependencies"]):
            raise RuntimeError("resolved metadata includes a non-registry dependency")
        for name, argv in [
            ("format", ["cargo", "fmt", "--", "--check"]),
            ("clippy", ["cargo", "clippy", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings"]),
            ("tests", ["cargo", "test", "--all-features", "--locked"]),
            ("default", ["cargo", "check", "--locked"]),
            ("portable", ["cargo", "check", "--no-default-features", "--locked"]),
            ("portable-forensics", ["cargo", "check", "--no-default-features", "--features", "forensics", "--locked"]),
            ("std-forensics", ["cargo", "check", "--features", "forensics", "--locked"]),
            ("feature-consumer", ["python3", "scripts/check-forensics-features.py", "--evidence-dir", str(evidence / "consumer")]),
            ("cli-build", ["cargo", "build", "--example", "filesystem-forensics", "--features", "forensics", "--locked"]),
        ]:
            run(name, argv)
        binary = Path(metadata["target_directory"]) / "debug/examples/filesystem-forensics"
        receipt["binary_sha256"] = digest(binary)
        receipt["passed"] = True
    except (OSError, ValueError, RuntimeError) as error:
        receipt["error"] = str(error)
    finally:
        receipt["source_sha256_after"] = snapshot(repository)
        receipt["source_unchanged"] = receipt["source_sha256_before"] == receipt["source_sha256_after"]
        receipt["passed"] = receipt["passed"] and receipt["source_unchanged"]
        (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": receipt["passed"], "receipt": str(evidence / "receipt.json")}))
    raise SystemExit(0 if receipt["passed"] else 1)


if __name__ == "__main__":
    main()
