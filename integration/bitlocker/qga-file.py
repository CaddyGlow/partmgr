#!/usr/bin/env python3
"""Transfer fixture files through an explicitly selected disposable guest's QGA.

Secret downloads are created exclusively with mode 0600. No guest commands run.
"""
import argparse
import base64
import json
import fcntl
import hashlib
import tempfile
import os
import socket


def call(path, command, arguments):
    # QGA is one serial command stream: coordinate cooperating host processes.
    name = hashlib.sha256(os.fsencode(os.path.realpath(path))).hexdigest()
    lock_path = os.path.join(tempfile.gettempdir(), 'partmgr-qga-' + name + '.lock')
    with open(lock_path, 'a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _call_locked(path, command, arguments)


def _call_locked(path, command, arguments):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(60)
        connection.connect(path)
        connection.sendall(json.dumps({'execute': command, 'arguments': arguments}).encode() + b'\n')
        with connection.makefile('rb') as stream:
            response = json.loads(stream.readline(2 * 1024 * 1024))
    if 'error' in response:
        raise RuntimeError(response['error'])
    return response['return']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('socket')
    parser.add_argument('direction', choices=['push', 'pull'])
    parser.add_argument('local')
    parser.add_argument('guest')
    args = parser.parse_args()
    upload = args.direction == 'push'
    # Download never truncates a previous artifact.
    local = open(args.local, 'rb') if upload else os.fdopen(os.open(args.local, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
    with local:
        handle = call(args.socket, 'guest-file-open', {'path': args.guest, 'mode': 'wb' if upload else 'rb'})
        try:
            while True:
                if upload:
                    data = local.read(65536)
                    if not data:
                        break
                    written = call(args.socket, 'guest-file-write', {'handle': handle, 'buf-b64': base64.b64encode(data).decode()})
                    if written['count'] != len(data):
                        raise IOError('short guest write')
                else:
                    result = call(args.socket, 'guest-file-read', {'handle': handle, 'count': 65536})
                    data = base64.b64decode(result['buf-b64'], validate=True)
                    if len(data) != result['count']:
                        raise IOError('guest read count mismatch')
                    local.write(data)
                    if result['eof']:
                        break
                    if not data:
                        raise IOError('guest read made no progress')
            if upload:
                call(args.socket, 'guest-file-flush', {'handle': handle})
            else:
                local.flush()
                os.fsync(local.fileno())
        finally:
            call(args.socket, 'guest-file-close', {'handle': handle})


if __name__ == '__main__':
    main()
