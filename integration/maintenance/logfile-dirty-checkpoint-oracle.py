#!/usr/bin/env python3
"""Observe explicit native 112-byte NTFS restart payloads, without replay.

Linux v6.12 NTFS_RESTART defines bytes 0..64; pinned dfir_ntfs
NTFSRestartArea defines optional fields through byte 112. Bytes 84..88
remain opaque. Referenced tables are not selected, loaded, or qualified.
"""
import hashlib
import pathlib
import runpy
import struct
import sys


def inventory(path):
    model = runpy.run_path(str(pathlib.Path(__file__).with_name("logfile-dirty-record-oracle.py")))
    envelopes = model["inventory"](path)
    data = path.read_bytes()
    rows = ["# source_sha256=" + hashlib.sha256(data).hexdigest(),
            "# copy lsn payload_sha256 major minor checkpoint open_attr_lsn names_lsn dirty_lsn transaction_lsn open_attr_bytes names_bytes dirty_bytes transaction_bytes usn_restart last_lsn cluster_bytes opaque84 usn_reference usn_base oldest_lsn"]
    for row in envelopes.splitlines():
        if row.startswith("#"):
            continue
        fields = row.split("\t")
        copy, lsn = map(int, fields[:2])
        if int(fields[4]) != 112 or int(fields[7]) != 2 or "," in fields[11]:
            raise ValueError("oracle requires native one-page 112-byte restart envelope")
        offset = int(fields[11])
        restart = model["unprotect"](data[copy * 4096:(copy + 1) * 4096], b"RSTR", 30)
        area = struct.unpack_from("<H", restart, 24)[0]
        bits = struct.unpack_from("<I", restart, area + 16)[0]
        position = ((lsn & ((1 << (64 - bits)) - 1)) * 8) % 4096
        page = model["unprotect"](data[offset:offset + 4096], b"RCRD", 40)
        payload = page[position + 48:position + 160]
        digest = hashlib.sha256(payload).hexdigest()
        if digest != fields[10]:
            raise ValueError("payload disagrees with independent envelope model")
        prefix = struct.unpack_from("<IIQQQQQIIII", payload)
        usn_restart, last_lsn, cluster = struct.unpack_from("<qQI", payload, 64)
        usn_reference, usn_base, oldest = struct.unpack_from("<QqQ", payload, 88)
        observed = (copy, lsn, digest, *prefix, usn_restart, last_lsn,
                    cluster, payload[84:88].hex(), usn_reference, usn_base, oldest)
        rows.append("\t".join(map(str, observed)))
    if path.read_bytes() != data:
        raise ValueError("source changed during checkpoint inventory")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: logfile-dirty-checkpoint-oracle.py INPUT OUTPUT (new file)")
    result = inventory(pathlib.Path(sys.argv[1]))
    with pathlib.Path(sys.argv[2]).open("x", encoding="ascii") as output:
        output.write(result)
