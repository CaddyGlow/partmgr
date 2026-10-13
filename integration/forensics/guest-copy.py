#!/usr/bin/env python3
"""Copy an explicitly selected closed guest artifact through QGA with a size cap.

Uses exclusive host files, records SHA256 and never prints evidence bytes.
This is transport of an already stable artifact, not a live acquisition workflow.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--guest-path", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--max-bytes", type=int, default=512 * 1024 * 1024)
    args = parser.parse_args()
    if args.max_bytes < 0:
        parser.error("negative byte ceiling")

    def call(command, arguments):
        with socket.socket(socket.AF_UNIX) as channel:
            channel.settimeout(60)
            channel.connect(args.socket)
            channel.sendall((json.dumps({"execute": command, "arguments": arguments}) + "\n").encode())
            response = bytearray()
            while b"\n" not in response:
                chunk = channel.recv(65536)
                if not chunk:
                    raise RuntimeError("guest agent response truncated")
                response.extend(chunk)
                if len(response) > 2 * 1024 * 1024:
                    raise RuntimeError("guest agent response ceiling exceeded")
        result = json.loads(response.split(b"\n", 1)[0])
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["return"]

    output = args.output.resolve()
    partial = output.with_name(output.name + ".partial")
    digest = hashlib.sha256()
    count = 0
    with partial.open("xb") as stream:
        handle = call("guest-file-open", {"path": args.guest_path, "mode": "rb"})
        try:
            while True:
                result = call("guest-file-read", {"handle": handle, "count": 256 * 1024})
                chunk = base64.b64decode(result.get("buf-b64", ""), validate=True)
                if len(chunk) != result.get("count"):
                    raise RuntimeError("guest file read count disagrees with bytes")
                if len(chunk) > args.max_bytes - count:
                    raise RuntimeError("guest artifact exceeds byte ceiling")
                stream.write(chunk)
                digest.update(chunk)
                count += len(chunk)
                if result.get("eof"):
                    break
                if not chunk:
                    raise RuntimeError("guest file read made no progress before EOF")
        finally:
            call("guest-file-close", {"handle": handle})
        stream.flush()
        os.fsync(stream.fileno())
    actual = digest.hexdigest()
    if args.expected_sha256 and actual != args.expected_sha256.lower():
        raise RuntimeError("guest artifact digest differs from expected stable artifact")
    os.link(partial, output)
    partial.unlink()
    print(json.dumps({"output": str(output), "bytes": count, "sha256": actual,
                      "hash_domain": "selected_closed_guest_file_bytes", "expected_digest_checked": bool(args.expected_sha256)}))


if __name__ == "__main__":
    main()
