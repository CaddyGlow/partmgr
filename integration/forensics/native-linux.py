#!/usr/bin/env python3
"""Guest-only read-only loop qualification with reproducible per-backend receipts.

Run as root inside a disposable Linux VM. This never uses sudo, mounts a
filesystem, or writes an existing device. Each loop uses a private closed backing
artifact and is detached before its temporary directory is removed.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import tempfile

SIZE = 8 * 1024 * 1024


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def put16(image, at, value):
    struct.pack_into("<H", image, at, value)


def put32(image, at, value):
    struct.pack_into("<I", image, at, value)


def fat_fixture(sector):
    image = bytearray(SIZE)
    image[510:512] = b"\x55\xaa"
    image[450] = 1
    put32(image, 454, 8)
    put32(image, 458, 2880 * 512 // sector)
    base = 8 * sector
    put16(image, base + 11, 512)
    image[base + 13] = 1
    put16(image, base + 14, 1)
    image[base + 16] = 2
    put16(image, base + 17, 224)
    put16(image, base + 19, 2880)
    image[base + 21] = 0xF8
    put16(image, base + 22, 9)
    image[base + 510:base + 512] = b"\x55\xaa"
    for copy in range(2):
        table = base + (1 + copy * 9) * 512
        image[table:table + 3] = b"\xf8\xff\xff"
        image[table + 3:table + 5] = b"\xff\x0f"  # cluster 2 EOC, cluster 3 free
        image[table + 6:table + 8] = b"\xff\x0f"  # cluster 4 orphan EOC
    root = base + 19 * 512
    for offset, name, cluster, size in [
        (0, b"LIVE    BIN", 2, 4),
        (32, b"\xe5ELETED BIN", 3, 7),
        (96, b"SLACK   TXT", 4, 5),
    ]:
        image[root + offset:root + offset + 11] = name
        image[root + offset + 11] = 0x20
        put16(image, root + offset + 26, cluster)
        put32(image, root + offset + 28, size)
    image[root + 128] = 0xE5
    image[root + 128 + 11] = 0x0F
    put16(image, root + 128 + 1, 0xD800)
    image[base + 33 * 512:base + 33 * 512 + 4] = b"FAT!"
    return image


def upstream_fixture():
    return bytes((offset & 255) ^ (((offset >> 9) >> (8 * (offset % 8))) & 255)
                 for offset in range(SIZE))


def command(args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    return {"command": list(map(str, args)), "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def run_device(binary, fixture, sector, test_name, environment):
    before = sha256(fixture)
    setup = subprocess.run(["losetup", "--find", "--show", "--read-only", "--sector-size",
                            str(sector), str(fixture)], text=True, capture_output=True, check=True)
    device = setup.stdout.strip()
    try:
        queried = subprocess.run(["blockdev", "--getss", device], text=True,
                                 capture_output=True, check=True).stdout.strip()
        if queried != str(sector):
            raise RuntimeError(f"logical sector mismatch: {queried} != {sector}")
        env = dict(os.environ, **environment(device, fixture, sector))
        result = command([str(binary), "--ignored", "--exact", test_name, "--nocapture"], env=env)
        after = sha256(fixture)
        executed = ("running 1 test" in result["stdout"] and test_name in result["stdout"]
                    and "test result: ok. 1 passed; 0 failed" in result["stdout"])
        result.update({"fixture_sha256_before": before, "fixture_sha256_after": after,
                       "fixture_bytes": fixture.stat().st_size, "device": device,
                       "logical_sector_size": sector,
                       "environment": environment(device, fixture, sector),
                       "immutable_fixture_verified": before == after,
                       "selected_test_executed": executed,
                       "passed": result["exit_code"] == 0 and before == after and executed})
        return result
    finally:
        subprocess.run(["losetup", "--detach", device], check=True, capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-binary", type=Path, required=True)
    parser.add_argument("--partmgr-binary", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    if platform.system() != "Linux" or os.geteuid() != 0:
        parser.error("run as root inside a disposable Linux VM; host sudo is not supported")
    binaries = {name: path.resolve(strict=True) for name, path in
                [("upstream", args.upstream_binary), ("partmgr", args.partmgr_binary)]}
    receipt = {"version": 1, "profile": "disposable-linux-readonly-loop",
               "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "platform": platform.uname()._asdict(),
               "runner_sha256": sha256(Path(__file__)),
               "binaries": {name: {"path": str(path), "sha256": sha256(path)}
                            for name, path in binaries.items()},
               "losetup": command(["losetup", "--version"]), "results": []}
    try:
        with tempfile.TemporaryDirectory(prefix="partmgr-native-forensics-", dir=args.workspace) as temporary:
            directory = Path(temporary)
            pattern = directory / "upstream-pattern.dd"
            with pattern.open("xb") as stream:
                stream.write(upstream_fixture())
            for sector in [512, 4096]:
                result = run_device(binaries["upstream"], pattern, sector,
                                    "native_device_geometry_byte_reads_bounds_and_concurrency",
                                    lambda device, fixture, size: {"VIRTDISK_TEST_DEVICE": device,
                                                                  "VIRTDISK_TEST_SECTOR_SIZE": str(size)})
                result["backend"] = "upstream-physical-disk"
                receipt["results"].append(result)
                fixture = directory / f"fat-mbr-{sector}.dd"
                with fixture.open("xb") as stream:
                    stream.write(fat_fixture(sector))
                result = run_device(binaries["partmgr"], fixture, sector,
                                    "native_fat_partition_equivalence_for_disposable_device",
                                    lambda device, fixture, size: {"PARTMGR_TEST_DEVICE": device,
                                                                  "PARTMGR_TEST_RAW": str(fixture),
                                                                  "PARTMGR_TEST_SECTOR_SIZE": str(size)})
                result["backend"] = "partmgr-raw-native-loop-equivalence"
                receipt["results"].append(result)
    except Exception as error:
        receipt["runner_error"] = {"type": type(error).__name__, "message": str(error)}
        if isinstance(error, subprocess.CalledProcessError):
            receipt["runner_error"].update({"command": error.cmd, "exit_code": error.returncode,
                                           "stdout": error.stdout, "stderr": error.stderr})
    receipt["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    receipt["passed"] = len(receipt["results"]) == 4 and all(result["passed"] for result in receipt["results"])
    with args.receipt.open("x") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"receipt": str(args.receipt), "passed": receipt["passed"]}))
    raise SystemExit(0 if receipt["passed"] else 1)


if __name__ == "__main__":
    main()
