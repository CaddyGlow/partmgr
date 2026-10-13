#!/usr/bin/env python3
"""Independent physical header inventory for the exact 1.1/4096/512 profile.

This never identifies active records, chooses a tail, or interprets transactions.
Offsets follow the pinned sources in docs/filesystem-ntfs-logfile-design.md.
The TSV is consumed by the explicitly enabled native Rust qualification gate.
"""

import hashlib
import pathlib
import struct
import sys


def inventory(source: pathlib.Path) -> str:
    data = source.read_bytes()
    if len(data) < 50 * 4096 or len(data) % 4096:
        raise ValueError("exact page-aligned native stream required")
    for offset in (0, 4096):
        page = data[offset:offset + 4096]
        if page[:4] != b"RSTR" or struct.unpack_from("<HH", page, 26) != (1, 1):
            raise ValueError("native 1.1 restart copies required")
        if struct.unpack_from("<II", page, 16) != (4096, 4096):
            raise ValueError("4096-byte geometry required")
    rows = ["# source_sha256=" + hashlib.sha256(data).hexdigest()]
    rows.append("# offset kind raw_sha256 header08 flags count position next last_end")
    for offset in range(8192, len(data), 4096):
        raw = data[offset:offset + 4096]
        digest = hashlib.sha256(raw).hexdigest()
        if raw == b"\xff" * 4096:
            rows.append(f"{offset}\tones\t{digest}")
            continue
        if raw == bytes(4096):
            rows.append(f"{offset}\tzero\t{digest}")
            continue
        if raw[:4] != b"RCRD":
            raise ValueError(f"unknown page signature at {offset}")
        usa, count = struct.unpack_from("<HH", raw, 4)
        if usa < 40 or usa % 2 or count != 9 or usa + count * 2 > 510:
            raise ValueError(f"USA placement at {offset}")
        page = bytearray(raw)
        for sector in range(1, count):
            trailer = sector * 512 - 2
            if raw[trailer:trailer + 2] != raw[usa:usa + 2]:
                raise ValueError(f"USA mismatch at {offset}, sector {sector}")
            page[trailer:trailer + 2] = raw[usa + 2 * sector:usa + 2 * sector + 2]
        union = struct.unpack_from("<Q", page, 8)[0]
        flags, pages, position, next_offset = struct.unpack_from("<IHHH", page, 16)
        last_end = struct.unpack_from("<Q", page, 32)[0]
        rows.append("\t".join(map(str, (offset, "rcrd", digest, union, flags,
                                         pages, position, next_offset, last_end))))
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: logfile-page-oracle.py INPUT OUTPUT (new file)")
    result = inventory(pathlib.Path(sys.argv[1]))
    with pathlib.Path(sys.argv[2]).open("x", encoding="ascii") as output:
        output.write(result)
