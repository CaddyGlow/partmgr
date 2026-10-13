#!/usr/bin/env python3
"""Exact explicit-copy 2.0 current-LSN bytes; no active-context selection.

LSN address decoding and 48-byte LFS envelopes follow pinned Linux fslog.c
and dfir_ntfs LogFile.py. Physical ordinary pages start at page 34. Fast
copies remain untouched; this models neither log recovery nor transactions.
"""

import hashlib
import pathlib
import struct
import sys

PAGE = 4096
ORDINARY = 34 * PAGE


def unprotect(raw, signature, minimum):
    if len(raw) != PAGE or raw[:4] != signature:
        raise ValueError("protected page signature or length")
    usa, count = struct.unpack_from("<HH", raw, 4)
    if usa < minimum or usa % 2 or count != 9 or usa + count * 2 > 510:
        raise ValueError("protected page USA bounds")
    fixed = bytearray(raw)
    for sector in range(1, count):
        end = sector * 512 - 2
        if raw[end:end + 2] != raw[usa:usa + 2]:
            raise ValueError("protected page torn trailer")
        fixed[end:end + 2] = raw[usa + sector * 2:usa + sector * 2 + 2]
    return fixed


def inventory(path):
    data = path.read_bytes()
    if len(data) < 50 * PAGE or len(data) % PAGE:
        raise ValueError("exact page-aligned stream required")
    rows = ["# source_sha256=" + hashlib.sha256(data).hexdigest(),
            "# copy current_lsn previous undo bytes client_seq client_index type tx flags payload_sha256 pages"]
    for copy in (0, 1):
        restart = unprotect(data[copy * PAGE:(copy + 1) * PAGE], b"RSTR", 30)
        if struct.unpack_from("<HH", restart, 26) != (0, 2):
            raise ValueError("exact version 2.0 required")
        if struct.unpack_from("<II", restart, 16) != (PAGE, PAGE):
            raise ValueError("exact 4096-byte geometry required")
        area = struct.unpack_from("<H", restart, 24)[0]
        if area < 30 or area % 8 or area + 44 > 510:
            raise ValueError("restart area bounds")
        file_size = struct.unpack_from("<Q", restart, area + 24)[0]
        bits = struct.unpack_from("<I", restart, area + 16)[0]
        length, client_offset = struct.unpack_from("<HH", restart, area + 20)
        record_size, data_start = struct.unpack_from("<HH", restart, area + 36)
        clients, free_head, in_use = struct.unpack_from("<HHH", restart, area + 8)
        if file_size != len(data) or bits != 67 - file_size.bit_length():
            raise ValueError("exact usable stream geometry required")
        if record_size != 48 or data_start < 64 or data_start % 8 or data_start >= PAGE:
            raise ValueError("exact envelope and data offset required")
        if clients != 1 or free_head != 65535 or in_use != 0:
            raise ValueError("single allocated native client required")
        if client_offset < 44 or area + length > PAGE or client_offset + 160 > length:
            raise ValueError("client record bounds")
        client = area + client_offset
        client_sequence = struct.unpack_from("<H", restart, client + 20)[0]
        lsn = struct.unpack_from("<Q", restart, area)[0]
        address = (lsn & ((1 << (64 - bits)) - 1)) * 8
        offset, position = divmod(address, PAGE)
        offset *= PAGE
        if not lsn or offset < ORDINARY or address >= file_size or position < data_start or position + 48 > PAGE:
            raise ValueError("current LSN is not an ordinary record address")
        page = unprotect(data[offset:offset + PAGE], b"RCRD", 40)
        usa, usa_count = struct.unpack_from("<HH", page, 4)
        if usa + usa_count * 2 > data_start:
            raise ValueError("USA overlaps ordinary record data")
        header = struct.unpack_from("<QQQIHHIIH", page, position)
        if header[0] != lsn or header[3] > 16 * 1024 * 1024:
            raise ValueError("exact LSN or payload size mismatch")
        if header[4:6] != (client_sequence, in_use):
            raise ValueError("record client does not match explicit restart context")
        if header[6] not in (1, 2) or header[8] & ~1:
            raise ValueError("unsupported envelope type or flags")
        ring_pages = (file_size - ORDINARY) // PAGE
        if header[3] + 48 >= ring_pages * (PAGE - data_start):
            raise ValueError("record fills or exceeds usable ordinary ring")
        if header[3] > PAGE - position - 48 and not header[8] & 1:
            raise ValueError("cross-page record lacks multipage flag")
        remaining = header[3]
        position += 48
        payload = bytearray()
        pages = []
        while True:
            if len(pages) >= ring_pages + 1:
                raise ValueError("record exceeds physical ordinary ring")
            pages.append(offset)
            count = min(remaining, PAGE - position)
            payload.extend(page[position:position + count])
            remaining -= count
            if not remaining:
                break
            offset += PAGE
            if offset == file_size:
                offset = ORDINARY
            position = data_start
            page = unprotect(data[offset:offset + PAGE], b"RCRD", 40)
            usa, usa_count = struct.unpack_from("<HH", page, 4)
            if usa + usa_count * 2 > data_start:
                raise ValueError("USA overlaps continuation data")
        fields = (copy, *header, hashlib.sha256(payload).hexdigest(), ",".join(map(str, pages)))
        rows.append("\t".join(map(str, fields)))
    if path.read_bytes() != data:
        raise ValueError("source changed during inventory")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: logfile-dirty-record-oracle.py INPUT OUTPUT (new file)")
    result = inventory(pathlib.Path(sys.argv[1]))
    with pathlib.Path(sys.argv[2]).open("x", encoding="ascii") as output:
        output.write(result)
