#!/usr/bin/env python3
"""Independent exact-record byte model for the native 1.1 fixture gate.

Uses explicit physical addresses and fixed-up bytes, never tail selection,
successor inference, transaction decoding, or replay. Output is created anew.
"""
import hashlib
import pathlib
import struct
import sys

PAGE = 4096


def fixed(raw, signature, minimum):
    if len(raw) != PAGE or raw[:4] != signature:
        raise ValueError("protected page signature/length")
    usa, count = struct.unpack_from("<HH", raw, 4)
    if usa < minimum or usa % 2 or count != 9 or usa + 18 > 510:
        raise ValueError("protected page USA bounds")
    result = bytearray(raw)
    for sector in range(1, count):
        trailer = sector * 512 - 2
        if raw[trailer:trailer + 2] != raw[usa:usa + 2]:
            raise ValueError("protected page torn trailer")
        result[trailer:trailer + 2] = raw[usa + 2 * sector:usa + 2 * sector + 2]
    return result


def inventory(path):
    data = path.read_bytes()
    restart = fixed(data[:PAGE], b"RSTR", 30)
    other = fixed(data[PAGE:2 * PAGE], b"RSTR", 30)
    if struct.unpack_from("<HH", restart, 26) != (1, 1):
        raise ValueError("exact version 1.1 required")
    area = struct.unpack_from("<H", restart, 24)[0]
    other_area = struct.unpack_from("<H", other, 24)[0]
    length = struct.unpack_from("<H", restart, area + 20)[0]
    if restart[area:area + length] != other[other_area:other_area + length]:
        raise ValueError("matching restart contexts required")
    file_size = struct.unpack_from("<Q", restart, area + 24)[0]
    bits = struct.unpack_from("<I", restart, area + 16)[0]
    data_start = struct.unpack_from("<H", restart, area + 38)[0]
    if file_size != len(data) or bits != 67 - file_size.bit_length():
        raise ValueError("exact usable stream geometry required")
    client = area + struct.unpack_from("<H", restart, area + 22)[0]
    lsns = sorted(set(struct.unpack_from("<Q", restart, offset)[0]
                      for offset in (area, client, client + 8)))
    rows = ["# source_sha256=" + hashlib.sha256(data).hexdigest(),
            "# lsn previous undo bytes client_seq client_index type tx flags payload_sha256 pages"]
    for lsn in lsns:
        address = (lsn & ((1 << (64 - bits)) - 1)) * 8
        offset, position = divmod(address, PAGE)
        offset *= PAGE
        if not lsn or offset < 4 * PAGE or address >= file_size or position < data_start or position + 48 > PAGE:
            raise ValueError("selected LSN is not an ordinary record address")
        page = fixed(data[offset:offset + PAGE], b"RCRD", 40)
        header = struct.unpack_from("<QQQIHHIIH", page, position)
        if header[0] != lsn or header[3] > 16 * 1024 * 1024:
            raise ValueError("exact LSN/record size")
        remaining = header[3]
        position += 48
        payload = bytearray()
        pages = []
        while True:
            if len(pages) > file_size // PAGE:
                raise ValueError("record exceeds physical ring")
            pages.append(offset)
            count = min(remaining, PAGE - position)
            payload.extend(page[position:position + count])
            remaining -= count
            if not remaining:
                break
            offset += PAGE
            if offset == file_size:
                offset = 4 * PAGE
            position = data_start
            page = fixed(data[offset:offset + PAGE], b"RCRD", 40)
        fields = [*header, hashlib.sha256(payload).hexdigest(), ",".join(map(str, pages))]
        rows.append("\t".join(map(str, fields)))
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: logfile-record-oracle.py INPUT OUTPUT (new file)")
    result = inventory(pathlib.Path(sys.argv[1]))
    with pathlib.Path(sys.argv[2]).open("x", encoding="ascii") as output:
        output.write(result)
