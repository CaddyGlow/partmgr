#!/usr/bin/env python3
"""Receive closed guest fixture artifacts on loopback; never replace prior evidence."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', required=True)
    parser.add_argument('--port', type=int, default=18428)
    args = parser.parse_args()
    directory = Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)

    class Receiver(BaseHTTPRequestHandler):
        def do_PUT(self):
            if not re.fullmatch(r'/[A-Za-z0-9_.-]{1,180}', self.path):
                self.send_error(400, 'invalid artifact name')
                return
            try:
                length = int(self.headers.get('Content-Length', '-1'))
            except ValueError:
                self.send_error(411)
                return
            if not 0 <= length <= 80 * 1024 * 1024:
                self.send_error(413)
                return
            destination = directory / self.path[1:]
            try:
                output = destination.open('xb')
            except FileExistsError:
                self.send_error(409, 'evidence already exists')
                return
            digest = hashlib.sha256()
            remaining = length
            with output:
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        # Keep the visibly partial file; never silently replace it.
                        self.send_error(400, 'incomplete artifact')
                        return
                    output.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                output.flush()
            print(f'closed {destination.name} bytes={length} sha256={digest.hexdigest()}', flush=True)
            self.send_response(201)
            self.end_headers()

    HTTPServer(('127.0.0.1', args.port), Receiver).serve_forever()


if __name__ == '__main__':
    main()
