#!/usr/bin/env python3
"""Compare closed native mtools FAT artifacts against CLI and Sleuth Kit.

Run in a disposable Linux test guest with dosfstools, mtools and sleuthkit.
All mutations precede closed-artifact inspection; no existing evidence is edited.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--family", choices=["fat12", "fat16", "fat32"], default="fat12")
    args = parser.parse_args()
    root = args.evidence_dir.resolve()
    root.mkdir(exist_ok=False)
    binary = args.binary.resolve(strict=True)
    receipt = {"version": 1, "profile": f"native-{args.family}-mtools-tsk-cli", "platform": platform.platform(),
               "binary_sha256": digest(binary), "runner_sha256": digest(Path(__file__)), "commands": [], "results": [], "passed": False}

    def run(argv, name, expected_exit=0):
        argv = [str(v) for v in argv]
        result = subprocess.run(argv, capture_output=True)
        (root / (name + ".stdout")).write_bytes(result.stdout)
        (root / (name + ".stderr")).write_bytes(result.stderr)
        receipt["commands"].append({"argv": argv, "exit_code": result.returncode,
                                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                                    "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
        if result.returncode != expected_exit:
            raise RuntimeError((argv, result.returncode, result.stderr.decode(errors="replace")))
        return result.stdout

    try:
        for tool in ["fls", "icat", "fsstat"]:
            run([tool, "-V"], tool + "-version")
        run(["mkfs.fat", "--help"], "mkfs-version")
        run(["mcopy", "-V"], "mtools-version")
        working = root / "native-working.dd"
        size = {"fat12": 1440 * 1024, "fat16": 16 << 20, "fat32": 64 << 20}[args.family]
        with working.open("xb") as stream:
            stream.truncate(size)
        run(["mkfs.fat", "-F", args.family.removeprefix("fat"), working], "format")
        live = root / "live-content.bin"
        live.write_bytes(bytes(range(256)) * 32)
        deleted = root / "deleted-content.bin"
        deleted.write_bytes(b"deleted-native-payload\n" * 227)
        reused = root / "reused-content.bin"
        reused.write_bytes(b"reused-cluster-native\n" * 350)
        run(["mcopy", "-i", working, live, "::LIVE.BIN"], "copy-live")
        run(["mcopy", "-i", working, deleted, "::deleted long file.txt"], "copy-deleted")
        run(["mdel", "-i", working, "::deleted long file.txt"], "native-delete")
        closed_deleted = root / "native-deleted.dd"
        closed_deleted.write_bytes(working.read_bytes())
        run(["mcopy", "-i", working, reused, "::REUSE.BIN"], "native-reuse")
        closed_reused = root / "native-reused.dd"
        closed_reused.write_bytes(working.read_bytes())
        for index, image in enumerate([closed_deleted, closed_reused]):
            before = digest(image)
            bpb = image.read_bytes()[:512]
            sector = int.from_bytes(bpb[11:13], "little")
            reserved = int.from_bytes(bpb[14:16], "little")
            fats = bpb[16]
            fat_sectors = int.from_bytes(bpb[22:24], "little")
            root_bytes = int.from_bytes(bpb[17:19], "little") * 32
            if root_bytes:
                root_offset = (reserved + fats * fat_sectors) * sector
            else:
                fat_sectors = int.from_bytes(bpb[36:40], "little")
                root_cluster = int.from_bytes(bpb[44:48], "little")
                cluster_bytes = bpb[13] * sector
                root_offset = (reserved + fats * fat_sectors) * sector + (root_cluster - 2) * cluster_bytes
                root_bytes = cluster_bytes
            flags = ["--format", "raw", "--sector-size", str(sector), "--assert-stable", "--acquisition-id", image.name,
                     "--stability-provider", "private-closed-native-artifact"]
            slots = [json.loads(line) for line in run([binary, "slots-fat", image, *flags, "--directory-offset", root_offset,
                                                      "--directory-length", root_bytes], f"{index}-slots").splitlines()]
            assert slots[-1]["type"] == "terminal" and slots[-1]["complete"]
            observations = [v for v in slots if v["type"] == "fat_slot"]
            live_slot = next(v for v in observations if bytes.fromhex(v["raw_hex"])[:11] == b"LIVE    BIN")
            assert live_slot["kind"] == "file" and not live_slot["post_terminator"]
            if index == 0:
                assert any(v["kind"] == "deleted_alias" for v in observations)
                assert any(v["kind"] == "deleted_lfn_fragment" for v in observations)
            listing = run(["fls", "-f", "fat", "-r", image], f"{index}-fls").decode()
            live_line = next(line for line in listing.splitlines() if line.endswith("LIVE.BIN"))
            inode = live_line.split(":", 1)[0].split()[-1]
            independent = run(["icat", "-f", "fat", image, inode], f"{index}-icat-live")
            assert independent == live.read_bytes()
            run(["fsstat", "-f", "fat", image], f"{index}-fsstat")
            output = root / f"exports-{index}"
            output.mkdir()
            exported = [json.loads(line) for line in run([binary, "extract-fat", image, *flags, "--directory-offset", root_offset,
                                                         "--directory-length", root_bytes, "--slot-offset", live_slot["volume_range"]["offset"],
                                                         "--output-dir", output], f"{index}-extract").splitlines()]
            assert exported[-1]["type"] == "terminal" and exported[-1]["complete"]
            content_files = [p for p in output.iterdir() if p.name.endswith(".partial") and ".jsonl" not in p.name]
            assert len(content_files) == 1 and content_files[0].read_bytes() == independent
            manifest = next(output.glob("*.jsonl.partial"))
            manifest_rows = [json.loads(line) for line in manifest.read_text().splitlines()]
            assert manifest_rows[-1]["type"] == "terminal" and manifest_rows[-1]["complete"]
            after = digest(image)
            assert before == after
            receipt["results"].append({"fixture": image.name, "fixture_sha256_before": before, "fixture_sha256_after": after,
                                       "immutable_fixture_verified": True, "native_deleted_slots_present": index == 0,
                                       "live_tsk_inode": inode, "output_sha256": hashlib.sha256(independent).hexdigest(),
                                       "native_expected_sha256": digest(live), "partmgr_output_sha256": digest(content_files[0]), "passed": True})
            if index == 0:
                # Derive a new artifact from the closed native deletion snapshot.
                # These corruptions are explicit controls, not native filesystem operations.
                derived = bytearray(image.read_bytes())
                patches = []

                def patch(offset, replacement, purpose):
                    original = bytes(derived[offset:offset + len(replacement)])
                    derived[offset:offset + len(replacement)] = replacement
                    patches.append({"volume_offset": offset, "before_hex": original.hex(),
                                    "after_hex": replacement.hex(), "purpose": purpose})

                lfn = next(v for v in observations if v["kind"] == "deleted_lfn_fragment")
                lfn_offset = lfn["volume_range"]["offset"]
                malformed = bytearray.fromhex(lfn["raw_hex"])
                malformed[0] = 0x47  # Last ordinal seven, with missing preceding fragments.
                malformed[12] = 9  # Invalid native LFN type.
                malformed[13] ^= 0xff  # Broken checksum association.
                malformed[26:28] = (7).to_bytes(2, "little")
                malformed[1:3] = (0xdc00).to_bytes(2, "little")  # Lone low surrogate.
                patch(lfn_offset, malformed, "malformed_lfn_no_authenticated_name")
                live_offset = live_slot["volume_range"]["offset"]
                timestamp_slot = bytearray.fromhex(live_slot["raw_hex"])
                timestamp_slot[13] = 199
                timestamp_slot[14:18] = bytes.fromhex("ffff0000")
                timestamp_slot[18:20] = bytes.fromhex("ffff")
                timestamp_slot[22:26] = bytes.fromhex("ffffffff")
                patch(live_offset, timestamp_slot, "raw_timestamp_invalid_date_time_edges")
                terminator = next(v for v in observations if v["kind"] == "terminator")
                slack_offset = terminator["volume_range"]["offset"] + 32
                assert slack_offset + 32 <= root_offset + root_bytes
                slack_alias = bytearray.fromhex(live_slot["raw_hex"])
                slack_alias[:11] = b"SLACK   BIN"
                patch(slack_offset, slack_alias, "valid_looking_alias_after_terminator")
                negative = root / "derived-negative-controls.dd"
                with negative.open("xb") as stream:
                    stream.write(derived)
                negative_before = digest(negative)
                negative_flags = [*flags]
                negative_flags[negative_flags.index("--acquisition-id") + 1] = negative.name
                raw_rows = [json.loads(line) for line in run(
                    [binary, "slots-fat", negative, *negative_flags, "--directory-offset", root_offset,
                     "--directory-length", root_bytes], "negative-slots").splitlines()]
                assert raw_rows[-1]["type"] == "terminal" and raw_rows[-1]["complete"]
                by_offset = {row["volume_range"]["offset"]: row for row in raw_rows if row["type"] == "fat_slot"}
                for change in patches:
                    assert by_offset[change["volume_offset"]]["raw_hex"] == change["after_hex"]
                assert by_offset[lfn_offset]["kind"] == "lfn_fragment"
                assert not by_offset[lfn_offset]["post_terminator"]
                assert by_offset[slack_offset]["kind"] == "file" and by_offset[slack_offset]["post_terminator"]
                rejected_output = root / "negative-slack-exports"
                rejected_output.mkdir()
                rejected = [json.loads(line) for line in run(
                    [binary, "extract-fat", negative, *negative_flags, "--directory-offset", root_offset,
                     "--directory-length", root_bytes, "--slot-offset", slack_offset,
                     "--output-dir", rejected_output], "negative-slack-extract", expected_exit=2).splitlines()]
                terminal = [row for row in rejected if row["type"] == "terminal"][-1]
                assert not terminal["complete"] and terminal["stop_reason"] == "invalid_bootstrap"
                assert not list(rejected_output.iterdir())
                negative_after = digest(negative)
                assert negative_before == negative_after and digest(image) == before
                receipt["results"].append({"fixture": negative.name, "derived_from": image.name,
                                           "parent_sha256_before": before, "parent_sha256_after": digest(image),
                                           "fixture_sha256_before": negative_before, "fixture_sha256_after": negative_after,
                                           "derivation_patches": patches, "immutable_fixture_verified": True,
                                           "malformed_lfn_raw_preserved": True, "timestamp_edges_raw_preserved": True,
                                           "post_terminator_alias_extraction_rejected": True,
                                           "negative_export_files": 0, "passed": True})
        receipt["passed"] = True
    finally:
        (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(root / "receipt.json")


if __name__ == "__main__":
    main()
