#!/usr/bin/env python3
"""Independent FAT12/raw CLI gate; requires an already built example binary."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture():
    data = bytearray(2880 * 512)
    def word(offset, value):
        data[offset:offset + 2] = value.to_bytes(2, "little")
    word(11, 512)
    data[13] = 1
    word(14, 1)
    data[16] = 2
    word(17, 224)
    word(19, 2880)
    data[21] = 0xF8
    word(22, 9)
    data[510:512] = b"\x55\xaa"
    for start in (512, 10 * 512):
        data[start:start + 3] = b"\xf8\xff\xff"
        data[start + 3:start + 6] = b"\x04\x00\x00"
        data[start + 6:start + 9] = b"\xff\x0f\x00"
    root = 19 * 512
    data[root:root + 11] = b"FILE    BIN"
    data[root + 11] = 0x20
    data[root + 13] = 31
    packed_date = ((2020 - 1980) << 9) | (1 << 5) | 2
    packed_time = (3 << 11) | (4 << 5) | 3
    for offset, value in ((14, packed_time), (16, packed_date), (18, packed_date),
                          (22, packed_time), (24, packed_date), (26, 2)):
        word(root + offset, value)
    data[root + 28:root + 32] = (700).to_bytes(4, "little")
    # A terminator then an alias-shaped negative control in slack.
    data[root + 64:root + 75] = b"SLACK   BIN"
    data[root + 64 + 11] = 0x20
    data[33 * 512:34 * 512] = b"A" * 512
    data[35 * 512:35 * 512 + 188] = b"B" * 188
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--ntfs-fixture-generator", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    image = evidence / "independent-fat12.dd"
    image.write_bytes(fixture())
    conflicting = evidence / "independent-fat12-conflicting-copies.dd"
    conflicting_bytes = fixture()
    conflicting_bytes[10 * 512 + 3:10 * 512 + 6] = b"\x03\x20\x00"
    conflicting.write_bytes(conflicting_bytes)
    conflicting_before = digest(conflicting)
    invalid = evidence / "invalid-bootstrap.dd"
    invalid.write_bytes(bytes(1024))
    before = digest(image)
    commands = []
    common = ["--format", "raw", "--sector-size", "512", "--assert-stable",
              "--acquisition-id", "cli-literal-fat12-v1", "--stability-provider",
              "closed-test-artifact"]
    directory = ["--directory-offset", str(19 * 512), "--directory-length", "96"]

    def run(name, command, extra=(), expected=0, source=image, assertion=True):
        flags = common if assertion else [x for x in common if x != "--assert-stable"]
        argv = [str(binary), command, str(source), *flags, *extra]
        result = subprocess.run(argv, capture_output=True, check=False)
        (evidence / (name + ".jsonl")).write_bytes(result.stdout)
        (evidence / (name + ".stderr")).write_bytes(result.stderr)
        commands.append({"name": name, "argv": argv, "exit_status": result.returncode})
        assert result.returncode == expected, (name, result.returncode, result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines() if line]

    slots = run("slots", "slots-fat", directory)
    observations = [row for row in slots if row["type"] == "fat_slot"]
    assert len(observations) == 3
    assert [row["post_terminator"] for row in observations] == [False, False, True]
    assert slots[-1]["type"] == "terminal" and slots[-1]["complete"]
    timeline = run("timeline", "timeline-fat", [*directory, "--utc-offset-seconds", "3600"])
    assert any(row["type"] == "timestamp" for row in timeline)
    assert timeline[-1]["complete"]
    temporary = evidence / "sort-temp"
    temporary.mkdir()
    sorted_rows = run("timeline-sorted", "timeline-fat", ["--directory-offset", str(19 * 512), "--directory-length", "32", "--utc-offset-seconds", "3600", "--sort", "--temporary-dir", str(temporary)])
    keys = [int(row["time"]["unix_ticks_100ns"]) for row in sorted_rows if row["type"] == "timestamp"]
    assert len(keys) == 3 and keys == sorted(keys)
    assert sorted_rows[-1]["coordinate_space"] == "record_ordinals"
    assert sorted_rows[-1]["complete"]
    unknown_zone = run("timeline-sort-unknown-zone", "timeline-fat", [*directory, "--sort", "--temporary-dir", str(temporary)], expected=2)
    assert unknown_zone[-1]["stop_reason"] == "unsupported_profile"
    invalid_calendar = run("timeline-sort-invalid-calendar", "timeline-fat", [*directory, "--utc-offset-seconds", "3600", "--sort", "--temporary-dir", str(temporary)], expected=2)
    assert invalid_calendar[-1]["stop_reason"] == "unsupported_profile"
    assert not any(row["type"] == "timestamp" for row in invalid_calendar)
    assert not list(temporary.iterdir())
    allocation = run("allocation", "allocation-fat")
    assert allocation[-1]["coordinate_space"] == "entry_ordinals"
    assert allocation[-1]["complete"]
    differences = run("copy-differences", "compare-fat-copies", source=conflicting)
    changed = [row for row in differences if row["type"] == "fat_copy_difference"]
    assert [row["other"]["cluster"] for row in changed] == [2, 3]
    assert all(row["meaningful_difference"] and row["raw_difference"] for row in changed)
    assert all(not row["baseline_is_historical_authority"] for row in changed)
    assert changed[0]["baseline"]["value"] == 4 and changed[0]["other"]["value"] == 3
    assert changed[0]["baseline"]["raw_hex"] == "0400" and changed[0]["other"]["raw_hex"] == "0320"
    assert changed[0]["other"]["volume_range"] == {"offset": 10 * 512 + 3, "length": 2}
    assert changed[0]["other"]["logical_disk_range"] == changed[0]["other"]["volume_range"]
    assert differences[-1]["complete"]
    chains = run("copy-chains", "compare-fat-chains", ["--start-cluster", "2", "--chain-transitions", "4"], source=conflicting)
    steps = [row for row in chains if row["type"] == "fat_copy_chain"]
    assert [(row["entry"]["copy"], row["entry"]["cluster"]) for row in steps] == [(0, 2), (0, 4), (1, 2), (1, 3)]
    assert steps[-1]["cycle_to"] == 2
    assert chains[-1]["complete"]
    bounded = run("copy-chain-bound", "compare-fat-chains", ["--start-cluster", "2", "--chain-transitions", "1"], expected=2, source=conflicting)
    assert bounded[-1]["resource_ceiling"] == "chain transitions"
    exhausted = run("copy-read-zero", "compare-fat-copies", ["--read-bytes", "0"], expected=2, source=conflicting)
    assert exhausted[-1]["resource_ceiling"] == "read_bytes"
    assert not any(row["type"] == "fat_copy_difference" for row in exhausted)
    exact = run("copy-exact-read-budget", "compare-fat-copies", ["--read-bytes", str(1024 + 4 * (2847 + 2)), "--records", str(2 * (2847 + 2))], source=conflicting)
    assert exact[-1]["complete"]
    short = run("copy-short-read-budget", "compare-fat-copies", ["--read-bytes", str(1024 + 4 * (2847 + 2) - 1)], expected=2, source=conflicting)
    assert short[-1]["resource_ceiling"] == "read_bytes"
    assert digest(conflicting) == conflicting_before
    output = evidence / "exports"
    output.mkdir()
    extraction = run("extract", "extract-fat", [*directory, "--slot-offset", str(19 * 512),
                                                "--output-dir", str(output)])
    assert extraction[-1]["complete"]
    artifact = output / "candidate-000000.partial"
    assert artifact.read_bytes() == b"A" * 512 + b"B" * 188
    manifest = [json.loads(line) for line in (output / "candidate-000000.jsonl.partial").read_text().splitlines()]
    assert manifest[-1]["type"] == "terminal" and manifest[-1]["complete"]
    context = next(row for row in manifest if row["type"] == "fat_candidate_context")
    assert not context["deleted_alias"]
    assert all(not item["contiguous_hypothesis"] for item in context["ranges"])
    assert all(item["ownership_complete"] for item in context["ranges"])
    stopped = run("read-zero", "slots-fat", [*directory, "--read-bytes", "0"], expected=2)
    assert stopped[-1]["stop_reason"] == "resource_limit"
    assert stopped[-1]["resource_ceiling"] == "read_bytes"
    assert not any(row["type"] == "fat_slot" for row in stopped)
    bootstrap = run("invalid-bootstrap", "allocation-fat", expected=2, source=invalid)
    assert bootstrap[-1]["stop_reason"] == "invalid_bootstrap"
    assert bootstrap[-1]["observations"] == 0
    run("missing-stability", "allocation-fat", expected=1, assertion=False)
    if Path("/dev/full").exists():
        argv = [str(binary), "slots-fat", str(image), *common, *directory]
        with open("/dev/full", "wb") as sink:
            result = subprocess.run(argv, stdout=sink, stderr=subprocess.PIPE, check=False)
        assert result.returncode == 1
        commands.append({"name": "output-failure", "argv": argv, "stdout": "/dev/full", "exit_status": result.returncode})
        (evidence / "output-failure.stderr").write_bytes(result.stderr)
    ntfs_hashes = {}
    if args.ntfs_fixture_generator:
        generator = args.ntfs_fixture_generator.resolve(strict=True)
        ntfs_dir = evidence / "ntfs"
        subprocess.run([str(generator), str(ntfs_dir)], check=True)
        ntfs_hashes = {path.name: digest(path) for path in ntfs_dir.glob("*.dd")}
        commands.append({"name": "ntfs-fixture-generation", "argv": [str(generator), str(ntfs_dir)], "exit_status": 0})
        clean = run("ntfs-inventory", "inventory-ntfs", source=ntfs_dir / "live.dd")
        assert clean[-1]["complete"]
        assert len([row for row in clean if row["type"] == "ntfs_slot"]) == 32
        sorted_ntfs = run("ntfs-timeline-sorted", "timeline-ntfs", ["--sort", "--temporary-dir", str(temporary)], source=ntfs_dir / "live.dd")
        keys = [int(row["time"]["unix_ticks_100ns"]) for row in sorted_ntfs if row["type"] == "timestamp"]
        assert keys and keys == sorted(keys)
        assert sorted_ntfs[-1]["complete"]
        dirty = run("ntfs-dirty", "inventory-ntfs", source=ntfs_dir / "dirty.dd")
        assert dirty[-1]["complete"]
        live_output = evidence / "ntfs-live-export"
        live_output.mkdir()
        live = run("ntfs-live", "extract-ntfs", ["--record", "24", "--output-dir", str(live_output)], source=ntfs_dir / "live.dd")
        assert live[-1]["complete"]
        assert (live_output / "candidate-000000.partial").read_bytes() == b"hello"
        for profile, expected_bytes in (("deleted-conflict", b"C" * 100), ("deleted-free", b"D" * 100), ("missing-bitmap", b"D" * 100)):
            recovered = evidence / (profile + "-export")
            recovered.mkdir()
            rows = run("ntfs-" + profile, "recover-ntfs", ["--record", "24", "--output-dir", str(recovered)], expected=2 if profile == "missing-bitmap" else 0, source=ntfs_dir / (profile + ".dd"))
            assert rows[-1]["complete"]  # byte traversal independent of earlier checks
            assert (recovered / "candidate-000000.partial").read_bytes() == expected_bytes
            manifest = [json.loads(line) for line in (recovered / "candidate-000000.jsonl.partial").read_text().splitlines()]
            assessment = next(row for row in manifest if row["type"] == "ntfs_reuse_assessment")
            assert assessment["allocation"] == ("allocated" if profile == "deleted-conflict" else "unknown" if profile == "missing-bitmap" else "free")
            assert bool(assessment["conflicting_current_owner"]) == (profile == "deleted-conflict")
            assert next(row for row in manifest if row["type"] == "ntfs_candidate_context")["historical_authenticity"] == "unproven"
        for command in ("inspect-usn", "inspect-logfile", "timeline-usn"):
            # The independent fixture deliberately has neither native journal
            # namespace nor supported restart pages: preserve explicit failure.
            rows = run("ntfs-" + command, command, expected=2, source=ntfs_dir / "live.dd")
            assert not rows[-1]["complete"]
            assert rows[-1]["stop_reason"] != "resource_limit"
            assert rows[-1]["causes"], "unsupported/invalid journal bootstrap must retain its cause"
        rows = run("ntfs-timeline-usn-sorted-missing", "timeline-usn", ["--sort", "--temporary-dir", str(temporary)], expected=2, source=ntfs_dir / "live.dd")
        assert not rows[-1]["complete"]
        assert any(row.get("causes") for row in rows if row["type"] == "terminal")
        assert not list(temporary.iterdir())
        assert ntfs_hashes == {path.name: digest(path) for path in ntfs_dir.glob("*.dd")}
    after = digest(image)
    assert before == after
    (evidence / "receipt.json").write_text(json.dumps({
        "fixture_profile": "independent-fat12-fragmented-live-slack-v1",
        "binary_sha256": digest(binary), "fixture_sha256_before": before,
        "fixture_sha256_after": after, "output_sha256": digest(artifact),
        "conflicting_fat_fixture_sha256_before_after": conflicting_before,
        "script_sha256": digest(Path(__file__)),
        "ntfs_fixture_generator_sha256": digest(args.ntfs_fixture_generator) if args.ntfs_fixture_generator else None,
        "ntfs_fixture_source_sha256": digest(Path(__file__).resolve().parents[1] / "tests/fixtures/ntfs_clean.rs") if args.ntfs_fixture_generator else None,
        "ntfs_fixture_hashes_before_after": ntfs_hashes,
        "commands": commands, "result": "passed",
    }, indent=2) + "\n")
    print(evidence / "receipt.json")


if __name__ == "__main__":
    main()
