#!/usr/bin/env python3
"""Read-only physical inventory of Windows-authored 2.0/4096/512 log pages.

Offsets: Linux v6.12 fs/ntfs3/fslog.c RECORD_PAGE_HDR and dfir_ntfs
ec3ae088 LogFile.py LogRecordPage / apply_fast_pages. No tail selection,
fast-copy application, active-window selection, or transaction interpretation.
Unknown flags are observations, never evidence of replay support.
"""

import hashlib
import pathlib
import struct
import sys

PAGE = 4096


def fixed(raw: bytes, minimum_usa: int, offset: int) -> tuple[bytes, int, int]:
    usa, count = struct.unpack_from("<HH", raw, 4)
    if usa < minimum_usa or usa % 2 or count != 9 or usa + count * 2 > 510:
        raise ValueError(f"invalid USA placement at {offset}")
    page = bytearray(raw)
    for sector in range(1, count):
        trailer = sector * 512 - 2
        if raw[trailer:trailer + 2] != raw[usa:usa + 2]:
            raise ValueError(f"USA mismatch at {offset}, sector {sector}")
        page[trailer:trailer + 2] = raw[usa + sector * 2:usa + sector * 2 + 2]
    return bytes(page), usa, count


def inventory(source: pathlib.Path) -> str:
    data = source.read_bytes()
    if len(data) < 50 * PAGE or len(data) % PAGE:
        raise ValueError("page-aligned native stream required")
    for offset in (0, PAGE):
        raw = data[offset:offset + PAGE]
        if raw[:4] != b"RSTR" or struct.unpack_from("<HH", raw, 26) != (0, 2):
            raise ValueError("exact native 2.0 restart copies required")
        if struct.unpack_from("<II", raw, 16) != (PAGE, PAGE):
            raise ValueError("4096-byte geometry required")
        fixed(raw, 30, offset)
    rows = ["# source_sha256=" + hashlib.sha256(data).hexdigest()]
    rows.append("# offset role kind raw_sha256 fixed_sha256 usa usa_count header08 flags count position next last_end fast_target")
    for offset in range(2 * PAGE, len(data), PAGE):
        raw = data[offset:offset + PAGE]
        role = "fast" if offset < 34 * PAGE else "ordinary"
        digest = hashlib.sha256(raw).hexdigest()
        if raw in (bytes(PAGE), b"\xff" * PAGE):
            kind = "zero" if raw[0] == 0 else "ones"
            rows.append(f"{offset}\t{role}\t{kind}\t{digest}")
            continue
        if raw[:4] != b"RCRD":
            raise ValueError(f"unknown page signature at {offset}")
        page, usa, count = fixed(raw, 40, offset)
        # 2.x fast-copy target occupies 0x3c..0x40, outside USA ending at 58.
        if role == "fast" and usa + count * 2 > 60:
            raise ValueError(f"USA overlaps fast-copy target at {offset}")
        header08 = struct.unpack_from("<Q", page, 8)[0]
        flags, pages, position, next_offset = struct.unpack_from("<IHHH", page, 16)
        last_end = struct.unpack_from("<Q", page, 32)[0]
        target = str(struct.unpack_from("<I", page, 60)[0]) if role == "fast" else "-"
        row = (offset, role, "rcrd", digest, hashlib.sha256(page).hexdigest(),
               usa, count, header08, flags, pages, position, next_offset,
               last_end, target)
        rows.append("\t".join(map(str, row)))
    if source.read_bytes() != data:
        raise ValueError("source changed during inventory")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: logfile-dirty-page-oracle.py INPUT OUTPUT (new file)")
    result = inventory(pathlib.Path(sys.argv[1]))
    with pathlib.Path(sys.argv[2]).open("x", encoding="ascii") as output:
        output.write(result)
