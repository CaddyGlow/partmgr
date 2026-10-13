#!/usr/bin/env python3
"""Independent explicit checkpoint table-anchor byte inventory, without replay.

Uses pinned Linux LFS_RECORD_HDR/LOG_REC_HDR layouts and the sibling model's
USA handling. Envelope bit 4 is observed opaquely, never interpreted. Table
contents and pointer targets are not declared semantically valid by this tool.
"""
import hashlib
import pathlib
import runpy
import struct
import sys

PAGE = 4096
FIRST = 34 * PAGE


def restart_table(data):
    """Bounded structural table check; field names follow Linux, not English.

    Linux 'used' is slot count and 'total' is allocated count. This checks
    stronger finite-chain invariants than Linux check_rstbl's unbounded walk.
    It assigns no meaning to allocated entry bodies.
    """
    if len(data) < 24:
        raise ValueError("short restart table")
    size, slots, allocated = struct.unpack_from("<HHH", data)
    goal, first, last = struct.unpack_from("<III", data, 12)
    if size < 4 or not slots or allocated > slots or 24 + size * slots > len(data):
        raise ValueError("restart table size or count")
    offsets = set(range(24, 24 + slots * size, size))
    links = {off: struct.unpack_from("<I", data, off)[0] for off in offsets}
    live = {off for off, link in links.items() if link == 0xffffffff}
    if len(live) != allocated:
        raise ValueError("allocated count disagrees with entry markers")
    if any(link not in offsets and link not in (0, 0xffffffff) for link in links.values()):
        raise ValueError("restart entry points outside slots")
    seen = set()
    current = first
    previous = 0
    while current:
        if current not in offsets or current in seen or current in live:
            raise ValueError("restart free chain invalid or cyclic")
        seen.add(current)
        previous, current = current, links[current]
    if previous != last or seen != offsets - live:
        raise ValueError("restart free-chain tail or membership mismatch")
    return {"entry_bytes": size, "slots": slots, "allocated": allocated,
            "free_goal": goal, "first_free": first, "last_free": last,
            "free_chain_entries": len(seen)}


def inventory(path):
    model = runpy.run_path(str(pathlib.Path(__file__).with_name("logfile-dirty-record-oracle.py")))
    checkpoint_model = runpy.run_path(str(pathlib.Path(__file__).with_name("logfile-dirty-checkpoint-oracle.py")))
    contexts = checkpoint_model["inventory"](path)
    data = path.read_bytes()
    fix = model["unprotect"]
    rows = ["# source_sha256=" + hashlib.sha256(data).hexdigest(),
            "# copy reference lsn previous undo bytes client_seq client_index type tx flags pages payload_sha256 redo_op undo_op redo_offset redo_bytes undo_offset undo_bytes redo_sha256"]
    for context in contexts.splitlines():
        if context.startswith("#"):
            continue
        fields = context.split("\t")
        copy = int(fields[0])
        restart = fix(data[copy * PAGE:(copy + 1) * PAGE], b"RSTR", 30)
        area = struct.unpack_from("<H", restart, 24)[0]
        bits = struct.unpack_from("<I", restart, area + 16)[0]
        start = struct.unpack_from("<H", restart, area + 38)[0]
        client = area + struct.unpack_from("<H", restart, area + 22)[0]
        sequence = struct.unpack_from("<H", restart, client + 20)[0]
        for name, index, expected_operation in (("open_attribute", 6, 29), ("attribute_names", 7, 30), ("dirty_pages", 8, 31)):
            lsn = int(fields[index])
            address = (lsn & ((1 << (64 - bits)) - 1)) * 8
            offset, position = divmod(address, PAGE)
            offset *= PAGE
            if not lsn or offset < FIRST or address >= len(data) or position < start or position + 48 > PAGE:
                raise ValueError("invalid explicit table anchor address")
            page = fix(data[offset:offset + PAGE], b"RCRD", 40)
            header = struct.unpack_from("<QQQIHHIIH", page, position)
            if header[0] != lsn or header[4:7] != (sequence, 0, 1) or header[8] & ~5:
                raise ValueError("exact table anchor envelope mismatch")
            remaining = header[3]
            if remaining + 48 >= ((len(data) - FIRST) // PAGE) * (PAGE - start):
                raise ValueError("table record exceeds usable ring")
            if remaining > PAGE - position - 48 and not header[8] & 1:
                raise ValueError("cross-page table record lacks multipage bit")
            position += 48
            payload = bytearray()
            pages = []
            while True:
                usa, count = struct.unpack_from("<HH", page, 4)
                if usa + count * 2 > start:
                    raise ValueError("USA overlaps table payload data")
                if len(pages) >= (len(data) - FIRST) // PAGE + 1:
                    raise ValueError("table payload exceeds ring")
                pages.append(offset)
                amount = min(remaining, PAGE - position)
                payload.extend(page[position:position + amount])
                remaining -= amount
                if not remaining:
                    break
                offset += PAGE
                if offset == len(data):
                    offset = FIRST
                position = start
                page = fix(data[offset:offset + PAGE], b"RCRD", 40)
            if len(payload) < 40:
                raise ValueError("short NTFS client envelope")
            client_header = struct.unpack_from("<HHHHHH", payload)
            redo_op, _, redo_off, redo_len, undo_off, undo_len = client_header
            if redo_op != expected_operation or redo_len != int(fields[index + 4]):
                raise ValueError("checkpoint table reference/type/length mismatch")
            lcn_count = struct.unpack_from("<H", payload, 14)[0]
            header_end = 32 + 8 * max(1, lcn_count)
            if header_end > len(payload):
                raise ValueError("client LCN header exceeds payload")
            for off, length in ((redo_off, redo_len), (undo_off, undo_len)):
                if off % 8 or (length and off < header_end) or off + length > len(payload):
                    raise ValueError("client redo/undo slice bounds")
            if name != "attribute_names":
                restart_table(payload[redo_off:redo_off + redo_len])
            observed = (copy, name, *header, ",".join(map(str, pages)),
                        hashlib.sha256(payload).hexdigest(), *client_header,
                        hashlib.sha256(payload[redo_off:redo_off + redo_len]).hexdigest())
            rows.append("\t".join(map(str, observed)))
    if path.read_bytes() != data:
        raise ValueError("source changed during table inventory")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: logfile-dirty-table-oracle.py INPUT OUTPUT (new file)")
    result = inventory(pathlib.Path(sys.argv[1]))
    with pathlib.Path(sys.argv[2]).open("x", encoding="ascii") as output:
        output.write(result)
