#!/usr/bin/env python3
"""Extract one UDF file through independent libudfread; bytes go to stdout."""
import ctypes as c
import sys

if len(sys.argv) != 4:
    raise SystemExit("usage: udf-native-extract.py LIBRARY IMAGE NATIVE_PATH")
lib = c.CDLL(sys.argv[1])
for name, args, result in [
    ("udfread_init", [], c.c_void_p),
    ("udfread_open", [c.c_void_p, c.c_char_p], c.c_int),
    ("udfread_file_open", [c.c_void_p, c.c_char_p], c.c_void_p),
    ("udfread_file_size", [c.c_void_p], c.c_int64),
    ("udfread_file_read", [c.c_void_p, c.c_void_p, c.c_size_t], c.c_ssize_t),
    ("udfread_file_close", [c.c_void_p], None),
    ("udfread_close", [c.c_void_p], None),
]:
    function = getattr(lib, name)
    function.argtypes = args
    function.restype = result
volume = lib.udfread_init()
if not volume:
    raise SystemExit("libudfread initialization failed")
file = None
try:
    if lib.udfread_open(volume, sys.argv[2].encode()) != 0:
        raise SystemExit("libudfread image open failed")
    file = lib.udfread_file_open(volume, sys.argv[3].encode())
    if not file:
        raise SystemExit("libudfread file open failed")
    remaining = lib.udfread_file_size(file)
    if remaining < 0:
        raise SystemExit("libudfread invalid file size")
    buffer = c.create_string_buffer(65536)
    while remaining:
        count = lib.udfread_file_read(file, buffer, min(remaining, len(buffer)))
        if count <= 0:
            raise SystemExit("libudfread incomplete file read")
        sys.stdout.buffer.write(buffer.raw[:count])
        remaining -= count
    if lib.udfread_file_read(file, buffer, 1) != 0:
        raise SystemExit("libudfread EOF mismatch")
finally:
    if file:
        lib.udfread_file_close(file)
    lib.udfread_close(volume)
