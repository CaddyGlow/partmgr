#!/usr/bin/env python3
"""Author footer-free ext3 logs independently and recover separate native clones.

This is a format/replay oracle, not a kernel-authored dirty-log acquisition or
qualification of partmgr's preflight. OUTPUT must not exist; failed runs remain.
"""
import hashlib
import json
import pathlib
import shutil
import struct
import subprocess
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(destination):
    destination.mkdir()
    source_path = pathlib.Path(__file__)
    (destination / "oracle-source.py").write_bytes(source_path.read_bytes())
    receipt = {"scope": "independently authored footer-free ext3 journal; e2fsprogs replay only",
               "script_sha256": digest(pathlib.Path(__file__)),
               "tools": {}, "commands": [], "models": [], "complete": False}

    def save():
        (destination / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

    def run(name, args, accepted=(0,)):
        command = [receipt["tools"][name]["path"], *map(str, args)]
        result = subprocess.run(command, capture_output=True, check=False)
        stem = f"command-{len(receipt['commands']):03d}"
        outputs = {}
        for label, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = destination / f"{stem}.{label}"
            path.write_bytes(data)
            outputs[label] = {"file": path.name, "sha256": digest(path)}
        receipt["commands"].append({"argv": command, "exit": result.returncode, **outputs})
        save()
        if result.returncode not in accepted:
            raise RuntimeError(f"native command failed: {command}; see {stem}")
        return result.stdout

    for name in ("mke2fs", "debugfs", "e2fsck"):
        found = shutil.which(name)
        if found is None:
            raise RuntimeError(f"missing native tool: {name}")
        tool = pathlib.Path(found).resolve()
        receipt["tools"][name] = {"path": str(tool), "sha256": digest(tool)}
    save()
    for name in receipt["tools"]:
        run(name, ["-V"])
    payload = bytes((i * 71 + i // 251) % 256 for i in range(131089))
    payload_path = destination / "payload.bin"
    payload_path.write_bytes(payload)
    for block_bytes in (1024, 2048, 4096):
        stem = f"ext3-b{block_bytes}"
        clean = destination / f"{stem}-clean.raw"
        with clean.open("xb") as stream:
            stream.truncate(16 << 20)
        run("mke2fs", ["-q", "-F", "-t", "ext3", "-b", block_bytes,
                       "-I", 128, "-O", "none,has_journal,filetype,sparse_super", clean])
        run("debugfs", ["-w", "-R", f"write {payload_path} /payload", clean])
        run("e2fsck", ["-fn", clean])
        image = bytearray(clean.read_bytes())
        locations = []
        for logical in range(5):
            value = run("debugfs", ["-R", f"bmap <8> {logical}", clean]).strip()
            locations.append(int(value))
        if len(set(locations)) != 5 or min(locations) <= 0:
            raise ValueError("native journal mapping is not five distinct blocks")
        journal_at = locations[0] * block_bytes
        journal = image[journal_at:journal_at + 1024]
        magic, kind, _, native_block, maximum, first, sequence, start = struct.unpack_from(
            ">8I", journal)
        features = struct.unpack_from(">I", journal, 40)[0]
        if (magic, kind, native_block, first, start) != (0xc03b3998, 4, block_bytes, 1, 0):
            raise ValueError("unexpected native inactive journal geometry")
        if maximum < 5 or features & ~1 or any(journal[36:40]) or any(journal[44:48]):
            raise ValueError("oracle requires bounded checksumless journal")
        target = int(block_bytes == 1024)
        block_at = target * block_bytes
        redo = bytearray(image[block_at:block_at + block_bytes])
        inside = 0 if block_bytes == 1024 else 1024
        # A valid opaque superblock field preserved by journal-only replay.
        marker = f"partmgr-foreign-preflight-{block_bytes}".encode("ascii")
        redo[inside + 136:inside + 200] = marker.ljust(64, b"\0")
        old_flags = struct.unpack_from("<I", image, 1024 + 96)[0]
        struct.pack_into("<I", image, 1024 + 96, old_flags | 4)
        struct.pack_into("<I", redo, inside + 96, old_flags | 4)
        descriptor = bytearray(block_bytes)
        struct.pack_into(">IIIII", descriptor, 0, magic, 1, sequence, target, 8)
        descriptor[20:36] = journal[48:64]
        commit = bytearray(block_bytes)
        struct.pack_into(">III", commit, 0, magic, 2, sequence)
        for logical, data in ((1, descriptor), (2, redo), (3, commit), (4, bytes(block_bytes))):
            at = locations[logical] * block_bytes
            image[at:at + block_bytes] = data
            (destination / f"{stem}-journal-{logical}.bin").write_bytes(data)
        struct.pack_into(">I", image, journal_at + 28, 1)
        dirty = destination / f"{stem}-dirty.raw"
        dirty.write_bytes(image)
        dirty_hash = digest(dirty)
        oracle = destination / f"{stem}-e2fsck.raw"
        shutil.copyfile(dirty, oracle)
        run("e2fsck", ["-fy", "-E", "journal_only", oracle], accepted=(0, 1))
        run("e2fsck", ["-fn", oracle])
        recovered = oracle.read_bytes()
        if recovered[1024 + 136:1024 + 200] != marker.ljust(64, b"\0"):
            raise ValueError("native replay did not preserve committed marker")
        if struct.unpack_from("<I", recovered, 1024 + 96)[0] & 4:
            raise ValueError("native replay left recovery flag set")
        observed_sequence, observed_start = struct.unpack_from(">II", recovered, journal_at + 24)
        if observed_start != 0:
            raise ValueError("native replay left active journal")
        if observed_sequence != (sequence + 2) & 0xffffffff:
            raise ValueError("native restart did not skip the first unconsumed transaction ID")
        dumped = destination / f"{stem}-payload.bin"
        run("debugfs", ["-R", f"dump /payload {dumped}", oracle])
        if dumped.read_bytes() != payload or digest(dirty) != dirty_hash:
            raise ValueError("payload changed or original dirty fixture modified")
        receipt["models"].append({"block_bytes": block_bytes, "sequence": sequence,
                                  "scan_next_sequence": (sequence + 1) & 0xffffffff,
                                  "expected_restart_sequence": (sequence + 2) & 0xffffffff,
                                  "native_empty_sequence": observed_sequence,
                                  "journal_blocks": locations, "target": target,
                                  "marker": marker.decode("ascii"),
                                  "files": {p.name: digest(p) for p in
                                            (clean, dirty, oracle, dumped)}})
        save()
    for tool in receipt["tools"].values():
        if digest(pathlib.Path(tool["path"])) != tool["sha256"]:
            raise ValueError("native tool changed during oracle")
    if digest(pathlib.Path(__file__)) != receipt["script_sha256"]:
        raise ValueError("oracle source changed during execution")
    receipt["artifacts_sha256"] = {path.name: digest(path) for path in sorted(destination.iterdir())
                                   if path.is_file() and path.name != "receipt.json"}
    receipt["complete"] = True
    save()


if __name__ == "__main__":
    if len(sys.argv) != 2 or not pathlib.Path(sys.argv[1]).is_absolute():
        raise SystemExit("usage: ext-foreign-preflight-oracle.py ABSOLUTE_NEW_OUTPUT")
    if any(c.isspace() or c in '"\\' for c in sys.argv[1]):
        raise SystemExit("output path must contain no whitespace, quotes or backslashes")
    main(pathlib.Path(sys.argv[1]))
