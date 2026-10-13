#!/usr/bin/env python3
"""Independently replay retained foreign-recovery cut images with e2fsprogs."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

RECEIPT = "d41db945ad24e9fe013fca1a6b0b69e826e03d358eaf8d9f28b491fa730a83de"
COLUMNS = "block_bytes case event model fault_kind selector pre_sha256 pre_path retried_sha256 retried_path restart_sequence".split()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized(data, journal_at):
    result = bytearray(data)
    result[journal_at + 24:journal_at + 28] = bytes(4)
    return result


def verify(args):
    args.out.mkdir()
    result = {"complete": False, "scope": "e2fsprogs replay of modeled interrupted private foreign recovery; no kernel-authored dirty fixture or hardware crash claim", "commands": [], "images": []}
    receipt_path = args.out / "verification.json"

    def save():
        receipt_path.write_text(json.dumps(result, indent=2) + "\n")

    def command(argv, accepted, checker_time=None):
        index = len(result["commands"])
        stdout = args.out / f"command-{index:04d}.stdout"
        stderr = args.out / f"command-{index:04d}.stderr"
        environment = dict(os.environ)
        overrides = {} if checker_time is None else {"E2FSCK_TIME": str(checker_time)}
        environment.update(overrides)
        with stdout.open("xb") as out, stderr.open("xb") as err:
            code = subprocess.run([str(v) for v in argv], env=environment, stdout=out, stderr=err, check=False).returncode
        result["commands"].append({"argv": [str(v) for v in argv], "exit": code,
                                   "environment_overrides": overrides,
                                   "stdout": {"path": stdout.name, "sha256": digest(stdout)},
                                   "stderr": {"path": stderr.name, "sha256": digest(stderr)}})
        save()
        if code not in accepted:
            raise ValueError(f"command {index} failed with {code}: {argv}")

    save()
    try:
        script = Path(__file__).resolve()
        shutil.copyfile(script, args.out / "verifier-source.py")
        corpus_receipt = args.corpus / "receipt.json"
        if digest(corpus_receipt) != RECEIPT:
            raise ValueError("pinned corpus receipt mismatch")
        provenance = json.loads(corpus_receipt.read_text())
        for name, expected in provenance["artifacts_sha256"].items():
            if Path(name).name != name or digest(args.corpus / name) != expected:
                raise ValueError(f"corpus artifact mismatch: {name}")
        tools = {}
        for name in ("e2fsck", "debugfs"):
            found = shutil.which(name)
            if found is None:
                raise ValueError(f"missing tool: {name}")
            path = Path(found).resolve()
            if digest(path) != provenance["tools"][name]["sha256"]:
                raise ValueError(f"native tool identity mismatch: {name}")
            tools[name] = path
        manifest = args.evidence / "cuts.tsv"
        with manifest.open(newline="") as stream:
            reader = csv.DictReader(stream, delimiter="\t")
            if reader.fieldnames != COLUMNS:
                raise ValueError("cut manifest columns mismatch")
            rows = list(reader)
        if not rows:
            raise ValueError("empty cut manifest")
        if any(set(row) != set(COLUMNS) or None in row.values() for row in rows):
            raise ValueError("malformed cut manifest row")
        shutil.copyfile(manifest, args.out / "cuts.tsv")
        models = {model["block_bytes"]: model for model in provenance["models"]}
        coverage = set()
        faults = set()
        identities = set()
        inputs = {manifest: digest(manifest), corpus_receipt: RECEIPT, script: digest(script)}
        inputs.update({args.corpus / name: expected for name, expected in provenance["artifacts_sha256"].items()})
        inputs.update({path: digest(path) for path in tools.values()})
        for row in rows:
            bs, event, case = (int(row[key]) for key in ("block_bytes", "event", "case"))
            model = row["model"]
            if bs not in models or event not in range(1, 9) or model not in ("immediate", "volatile"):
                raise ValueError("invalid cut profile")
            if (bs, case) in identities:
                raise ValueError("duplicate cut case")
            identities.add((bs, case))
            coverage.add((bs, event, model))
            kind, selector = row["fault_kind"], int(row["selector"])
            if event % 2 == 0:
                valid = kind in ("flush-none", "flush-persist") and selector == 0
            else:
                size = bs if event == 1 else 1 if event == 7 else 4
                valid = ((kind == "write-prefix" and 0 <= selector <= size)
                         or (kind == "write-mask" and size == 4 and 0 <= selector < 16))
            if not valid:
                raise ValueError("invalid fault selector")
            fault = (bs, event, model, kind, selector)
            if fault in faults:
                raise ValueError("duplicate fault case")
            faults.add(fault)
            for prefix in ("pre", "retried"):
                sha, relative = row[prefix + "_sha256"], row[prefix + "_path"]
                if relative != f"images/{sha}.raw" or len(sha) != 64:
                    raise ValueError("unsafe or unbound cut image path")
                bytes.fromhex(sha)
                path = args.evidence / relative
                if path not in inputs:
                    inputs[path] = digest(path)
                if inputs[path] != sha:
                    raise ValueError("cut image hash mismatch")
        expected_coverage = {(bs, event, model) for bs in models for event in range(1, 9)
                             for model in ("immediate", "volatile")}
        if coverage != expected_coverage:
            raise ValueError("incomplete event/model coverage")
        expected_faults = set()
        for bs, event, model in expected_coverage:
            if event % 2 == 0:
                selectors = [("flush-none", 0), ("flush-persist", 0)]
            else:
                size = bs if event == 1 else 1 if event == 7 else 4
                inside = 0 if bs == 1024 else 1024
                prefixes = {0, 1, 511, 512, 1023, bs // 2, bs - 1, bs,
                            inside + 137, inside + 150, inside + 199} if event == 1 else set(range(size + 1))
                selectors = [("write-prefix", n) for n in prefixes if n <= size]
                if size == 4:
                    selectors += [("write-mask", n) for n in range(16)]
            expected_faults.update((bs, event, model, kind, selector) for kind, selector in selectors)
        if faults != expected_faults:
            raise ValueError("incomplete fault selector matrix")
        # Preserve each case, while running native tools once per distinct image.
        unique = sorted({(int(row["block_bytes"]), row["pre_sha256"], row["pre_path"]) for row in rows})
        expected_images = {bs: (args.corpus / f"ext3-b{bs}-e2fsck.raw").read_bytes() for bs in models}
        expected_payload = (args.corpus / "payload.bin").read_bytes()
        for index, (bs, sha, relative) in enumerate(unique):
            original = args.evidence / relative
            model = models[bs]
            journal_at = model["journal_blocks"][0] * bs
            expected = expected_images[bs]
            checker_time = int.from_bytes(expected[1088:1092], "little")
            if checker_time == 0 or int.from_bytes(expected[1072:1076], "little") != checker_time:
                raise ValueError("pinned oracle checker timestamps disagree")
            clone = args.out / f"image-{index:03d}-native.raw"
            shutil.copyfile(original, clone)
            # First check is read-only and precedes any repair/replay operation.
            command([tools["e2fsck"], "-fn", original], {0, 4}, checker_time)
            if digest(original) != sha:
                raise ValueError("read-only native check modified cut image")
            command([tools["e2fsck"], "-fy", "-E", "journal_only", clone], {0, 1}, checker_time)
            after = digest(clone)
            command([tools["e2fsck"], "-fn", clone], {0}, checker_time)
            if digest(clone) != after:
                raise ValueError("read-only post-replay check modified clone")
            actual = clone.read_bytes()
            before = original.read_bytes()
            before_sequence = int.from_bytes(before[journal_at + 24:journal_at + 28], "big")
            before_start = int.from_bytes(before[journal_at + 28:journal_at + 32], "big")
            before_features = int.from_bytes(before[1120:1124], "little")
            if (before_start not in (0, 1) or before_sequence not in (1, 3)
                    or before_features not in (2, 6)
                    or (before_start == 0 and before_sequence != 3)
                    or (before_features == 2 and before_start != 0)):
                raise ValueError("cut controls outside pinned transaction model")
            # Native recovery advances an already empty dirty journal as well.
            # Rust retains its previously published, whole-journal-excluded ID.
            expected_sequence = (3 if before_sequence == 1 else 4) if before_features & 4 else before_sequence
            if int.from_bytes(actual[journal_at + 24:journal_at + 28], "big") != expected_sequence:
                raise ValueError("native recovery restart sequence mismatch")
            if normalized(actual, journal_at) != normalized(expected, journal_at):
                raise ValueError(f"native recovered full-image mismatch: {bs}/{sha}")
            if actual[journal_at + 28:journal_at + 32] != bytes(4):
                raise ValueError("native journal remains active")
            payload = args.out / f"image-{index:03d}-payload.bin"
            command([tools["debugfs"], "-R", f"dump /payload {payload}", clone], {0})
            if payload.read_bytes() != expected_payload:
                raise ValueError("complete native payload mismatch")
            for row in rows:
                if int(row["block_bytes"]) == bs and row["pre_sha256"] == sha:
                    retry = (args.evidence / row["retried_path"]).read_bytes()
                    if normalized(retry, journal_at) != normalized(actual, journal_at):
                        raise ValueError("Rust/native cold retry mismatch")
                    restart_sequence = int.from_bytes(retry[journal_at + 24:journal_at + 28], "big")
                    if restart_sequence != model["expected_restart_sequence"]:
                        raise ValueError("Rust restart sequence differs from independent corpus model")
                    if restart_sequence != int(row["restart_sequence"]):
                        raise ValueError("Rust restart sequence observation mismatch")
            result["images"].append({"block_bytes": bs, "pre_sha256": sha, "native_path": clone.name,
                                     "native_sha256": after, "native_restart_sequence": int.from_bytes(actual[journal_at + 24:journal_at + 28], "big")})
            save()
        for path, expected in inputs.items():
            if digest(path) != expected:
                raise ValueError(f"verification input changed: {path}")
        result.update({"complete": True, "cases": len(rows), "unique_pre_images": len(unique),
                       "input_sha256": {str(path): sha for path, sha in inputs.items()}})
        result["artifacts_sha256"] = {str(path.relative_to(args.out)): digest(path) for path in sorted(args.out.rglob("*"))
                                      if path.is_file() and path != receipt_path}
        save()
        return 0
    except (OSError, ValueError, KeyError) as error:
        result["error"] = str(error)
        save()
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "corpus", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    if not all(path.is_absolute() for path in vars(options).values()):
        parser.error("all paths must be absolute")
    if any(char.isspace() or char in '\\"' for char in str(options.out)):
        parser.error("output path must be unambiguous to debugfs")
    sys.exit(verify(options))
