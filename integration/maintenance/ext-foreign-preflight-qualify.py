#!/usr/bin/env python3
"""Qualify foreign JBD preflight or private recovery and fail-closed bindings."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys

GATE = "fs_ext::jbd::foreign::native::native_foreign_preflight_matches_independent_e2fsprogs_overlay"
RECOVERY_GATE = "fs_ext::jbd::foreign::native::native_foreign_recovery_matches_independent_e2fsprogs_overlay"
CUTS_GATE = "fs_ext::jbd::foreign::native::native_foreign_recovery_cuts_match_independent_e2fsprogs_overlay"
RECEIPT_SHA256 = "d41db945ad24e9fe013fca1a6b0b69e826e03d358eaf8d9f28b491fa730a83de"


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(paths):
    return {str(path): file_hash(path) for path in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "corpus", "source-root", "out"):
        parser.add_argument("--" + name, required=True, type=pathlib.Path)
    parser.add_argument("--recovery", action="store_true", help="qualify private checksumless recovery against full native images")
    parser.add_argument("--cuts", action="store_true", help="retain actual interrupted writer images and independently verify native replay")
    args = parser.parse_args()
    if args.cuts:
        args.recovery = True
    for name in ("binary", "corpus", "source_root", "out"):
        path = getattr(args, name)
        if not path.is_absolute():
            parser.error(f"--{name.replace('_', '-')} must be absolute")
    args.out.mkdir()  # Never reuse a prior qualification or overwrite its logs.
    result = {"scope": "read-only foreign JBD preflight on independently authored ext3 and e2fsprogs replay clones; no kernel dirty fixture or recovery writer qualification",
              "complete": False, "runs": []}
    if args.recovery:
        result["scope"] = "private checksumless foreign JBD recovery on disposable buffers compared with complete e2fsprogs replay images; no kernel dirty fixture or native crash qualification"
    if args.cuts:
        result["scope"] = "modeled interrupted private foreign recovery with independent e2fsprogs replay; no kernel-authored dirty fixture or hardware crash qualification"
    final = args.out / "qualification.json"

    def save():
        final.write_text(json.dumps(result, indent=2) + "\n")

    save()
    try:
        script = pathlib.Path(__file__).resolve()
        shutil.copyfile(script, args.out / "runner-source.py")
        receipt = args.corpus / "receipt.json"
        if file_hash(receipt) != RECEIPT_SHA256:
            raise ValueError("fixed corpus receipt hash mismatch")
        provenance = json.loads(receipt.read_text())
        if provenance.get("complete") is not True:
            raise ValueError("incomplete independent oracle receipt")
        for name, expected in provenance["artifacts_sha256"].items():
            if pathlib.Path(name).name != name or file_hash(args.corpus / name) != expected:
                raise ValueError(f"corpus artifact hash mismatch: {name}")
        tools = {}
        for name in ("mke2fs", "debugfs", "e2fsck"):
            found = shutil.which(name)
            if found is None:
                raise ValueError(f"missing native tool: {name}")
            path = pathlib.Path(found).resolve()
            expected = provenance["tools"][name]["sha256"]
            if file_hash(path) != expected:
                raise ValueError(f"native tool identity mismatch: {name}")
            tools[name] = path
        sources = list((args.source_root / "src").rglob("*.rs"))
        if not sources:
            raise ValueError("compiled source root has no Rust sources")
        sources += [args.source_root / "Cargo.toml", args.source_root / "Cargo.lock",
                    args.source_root / "integration/maintenance/ext-foreign-preflight-oracle.py", script]
        sources += list((args.source_root / "tests").rglob("*.rs"))
        if args.cuts:
            sources.append(args.source_root / "integration/maintenance/ext-foreign-cuts-verify.py")
        before = {"source": snapshot(sources),
                  "corpus": snapshot(path for path in args.corpus.iterdir() if path.is_file()),
                  "binary": snapshot([args.binary]), "tools": snapshot(tools.values())}
        result["bindings_before"] = before
        save()
        base_env = dict(os.environ)
        base_env.update({"PARTMGR_EXT_FOREIGN_CORPUS": str(args.corpus),
                         "PARTMGR_EXT_FOREIGN_RECEIPT": str(receipt),
                         "PARTMGR_GATE_SOURCE_ROOT": str(args.source_root),
                         "PARTMGR_EXT_FOREIGN_MKE2FS": str(tools["mke2fs"]),
                         "PARTMGR_EXT_FOREIGN_DEBUGFS": str(tools["debugfs"]),
                         "PARTMGR_EXT_FOREIGN_E2FSCK": str(tools["e2fsck"])})
        positive = args.out / "positive-evidence"
        command = [str(args.binary), "--ignored", "--exact", CUTS_GATE if args.cuts else RECOVERY_GATE if args.recovery else GATE, "--nocapture"]

        def run(name, evidence, changed):
            env = dict(base_env)
            env["PARTMGR_EXT_FOREIGN_EVIDENCE"] = str(evidence)
            env.update(changed)
            stdout = args.out / (name + ".stdout")
            stderr = args.out / (name + ".stderr")
            with stdout.open("xb") as out, stderr.open("xb") as err:
                process = subprocess.run(command, env=env, stdout=out, stderr=err, check=False)
            result["runs"].append({"name": name, "argv": command, "bindings": {
                key: value for key, value in env.items() if key.startswith("PARTMGR_")},
                "exit": process.returncode, "stdout": {"path": str(stdout), "sha256": file_hash(stdout)},
                "stderr": {"path": str(stderr), "sha256": file_hash(stderr)}})
            save()
            return process.returncode

        passed = run("positive", positive, {}) == 0
        absent = args.out / "intentionally-absent"
        for name, changed in (
            ("missing-receipt", {"PARTMGR_EXT_FOREIGN_RECEIPT": str(absent / "receipt.json")}),
            ("missing-image", {"PARTMGR_EXT_FOREIGN_CORPUS": str(absent / "corpus")}),
            ("missing-source", {"PARTMGR_GATE_SOURCE_ROOT": str(absent / "source")}),
            ("missing-tool", {"PARTMGR_EXT_FOREIGN_E2FSCK": str(absent / "e2fsck")}),
        ):
            rejected = run(name, args.out / (name + "-evidence"), changed) != 0
            passed = passed and rejected
        rejected = run("reused-evidence", positive, {}) != 0
        passed = passed and rejected
        # Exit zero alone is insufficient: require the exact gate's artifacts
        # and explicit completed-scope report (a mistyped libtest filter runs zero).
        for name in ("report.txt", "receipt.txt", "observations.txt", "gate-binary",
                     "source-start.sha256", "source-end.sha256", "corpus-start.sha256", "corpus-end.sha256"):
            if not (positive / name).is_file():
                raise ValueError(f"positive gate artifact missing: {name}")
        if "complete=true\n" not in (positive / "report.txt").read_text():
            raise ValueError("positive gate report incomplete")
        mode = "true" if args.recovery else "false"
        if f"recovery={mode}\n" not in (positive / "receipt.txt").read_text():
            raise ValueError("positive gate recovery mode mismatch")
        if args.cuts:
            if "cut_artifacts=true\n" not in (positive / "receipt.txt").read_text():
                raise ValueError("positive gate cut artifact mode mismatch")
            verifier = args.source_root / "integration/maintenance/ext-foreign-cuts-verify.py"
            verifier_command = [sys.executable, str(verifier), "--evidence", str(positive),
                                "--corpus", str(args.corpus), "--out", str(args.out / "native-cuts")]
            with (args.out / "native-verifier.stdout").open("xb") as stdout, (args.out / "native-verifier.stderr").open("xb") as stderr:
                code = subprocess.run(verifier_command, stdout=stdout, stderr=stderr, check=False).returncode
            result["native_verifier"] = {"argv": verifier_command, "exit": code, "source_sha256": file_hash(verifier)}
            save()
            native_receipt = json.loads((args.out / "native-cuts/verification.json").read_text())
            if code != 0 or native_receipt.get("complete") is not True:
                raise ValueError("independent native cut verification failed")
        if args.recovery:
            for block_bytes in (1024, 2048, 4096):
                recovered = positive / f"profile-b{block_bytes}-partmgr-recovered.raw"
                native = args.corpus / f"ext3-b{block_bytes}-e2fsck.raw"
                if file_hash(recovered) != file_hash(native):
                    raise ValueError(f"full native recovery image mismatch: {block_bytes}")
        for stem in ("source", "corpus"):
            if (positive / (stem + "-start.sha256")).read_bytes() != (positive / (stem + "-end.sha256")).read_bytes():
                raise ValueError(f"positive gate {stem} changed")
        if file_hash(positive / "gate-binary") != before["binary"][str(args.binary)]:
            raise ValueError("captured gate binary identity mismatch")
        after = {"source": snapshot(sources), "corpus": snapshot(path for path in args.corpus.iterdir() if path.is_file()),
                 "binary": snapshot([args.binary]), "tools": snapshot(tools.values())}
        result["bindings_after"] = after
        if before != after:
            raise ValueError("qualification inputs changed")
        result["artifacts_sha256"] = {
            str(path.relative_to(args.out)): file_hash(path)
            for path in sorted(args.out.rglob("*")) if path.is_file() and path != final}
        result["complete"] = passed
        save()
        return 0 if passed else 1
    except (OSError, ValueError, KeyError) as error:
        result["error"] = str(error)
        save()
        return 1


if __name__ == "__main__":
    sys.exit(main())
