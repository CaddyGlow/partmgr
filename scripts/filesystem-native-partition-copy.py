#!/usr/bin/env python3
"""Check staged FAT/exFAT/ext2 GPT/MBR copy pipelines with independent tools."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import uuid
import zlib

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1 << 20), b''):
            result.update(chunk)
    return result.hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def payload_models():
    return {'PAYLOAD.BIN': bytes([0x76]) * 512,
            'BIG.BIN': bytes((index * 37 + 11) % 251 for index in range(4099)),
            'NEST/CHILD.BIN': bytes((index * 19 + 7) % 253 for index in range(1025))}


def native_ext_path(name):
    return {'PAYLOAD.BIN': 'PAYLOAD BIN', 'BIG.BIN': 'BIG     BIN',
            'NEST/CHILD.BIN': 'NEST       /CHILD   BIN'}[name]


def source_fixture():
    # Independent FAT12 source: noncontiguous multi-cluster files and nested directory.
    body = bytearray(128 * 512)
    for offset, value in [(11, 512), (14, 1), (17, 16), (19, 128), (22, 1)]:
        struct.pack_into('<H', body, offset, value)
    body[0:3] = bytes([0xeb, 0x3c, 0x90])
    body[3:11] = b'PMFS    '
    body[38] = 0x29
    body[43:54] = b'NO NAME    '
    body[54:62] = b'FAT12   '
    body[13] = body[16] = 1
    body[21] = 0xf8
    body[510:512] = b'\x55\xaa'

    def fat(cluster, value):
        offset = 512 + cluster * 3 // 2
        current = int.from_bytes(body[offset:offset + 2], 'little')
        updated = (current & 0x000f) | (value << 4) if cluster & 1 else (current & 0xf000) | value
        body[offset:offset + 2] = updated.to_bytes(2, 'little')

    def entry(offset, name, cluster, length, directory=False):
        require(len(name) == 11, 'independent fixture short-name geometry')
        body[offset:offset + 11] = name
        body[offset + 11] = 0x10 if directory else 0x20
        struct.pack_into('<H', body, offset + 26, cluster)
        struct.pack_into('<I', body, offset + 28, length)

    def content(chain, data):
        for index, cluster in enumerate(chain):
            fat(cluster, chain[index + 1] if index + 1 < len(chain) else 0xfff)
            offset = (cluster + 1) * 512
            body[offset:offset + 512] = bytes([0xa5]) * 512
            chunk = data[index * 512:(index + 1) * 512]
            body[offset:offset + len(chunk)] = chunk

    models = payload_models()
    fat(0, 0xff8)
    fat(1, 0xfff)
    fat(3, 0xfff)
    entry(1024, b'PAYLOAD BIN', 2, len(models['PAYLOAD.BIN']))
    entry(1056, b'BIG     BIN', 4, len(models['BIG.BIN']))
    entry(1088, b'NEST       ', 3, 0, True)
    entry(2048, b'.          ', 3, 0, True)
    entry(2080, b'..         ', 0, 0, True)
    entry(2112, b'CHILD   BIN', 13, len(models['NEST/CHILD.BIN']))
    content([2], models['PAYLOAD.BIN'])
    content([4, 7, 5, 10, 8, 6, 11, 9, 12], models['BIG.BIN'])
    content([13, 15, 14], models['NEST/CHILD.BIN'])
    return body


def inspect_table(path, scheme, filesystem_bytes, mbr_type, gpt_type):
    # Decode table fields and CRCs independently of partmgr.
    with path.open('rb') as disk:
        total = path.stat().st_size
        require(total == filesystem_bytes + (2 << 20), 'wrong disk size')
        mbr = disk.read(512)
        require(mbr[510:512] == b'\x55\xaa', 'missing MBR signature')
        if scheme == 'mbr':
            start, count = struct.unpack_from('<II', mbr, 454)
            require(mbr[446] == 0 and mbr[450] == mbr_type, 'wrong MBR type/boot flag')
            require(start == 2048 and count == filesystem_bytes // 512, 'wrong MBR region')
            require(not any(mbr[462:510]), 'unexpected additional MBR partitions')
            return
        require(mbr[450] == 0xee, 'missing protective MBR')
        arrays = []
        for here, other in [(1, total // 512 - 1), (total // 512 - 1, 1)]:
            disk.seek(here * 512)
            header = bytearray(disk.read(512))
            require(header[:8] == b'EFI PART', 'missing GPT signature')
            revision, size, crc, reserved = struct.unpack_from('<IIII', header, 8)
            require(revision == 0x10000 and size == 92 and reserved == 0, 'wrong GPT header geometry')
            current, alternate, usable_first, usable_last = struct.unpack_from('<QQQQ', header, 24)
            require((current, alternate) == (here, other), 'wrong reciprocal GPT LBAs')
            header[16:20] = bytes(4)
            require(zlib.crc32(header[:size]) == crc, 'GPT header CRC mismatch')
            table_lba, count, stride, table_crc = struct.unpack_from('<QIII', header, 72)
            require(count == 128 and stride == 128, 'unexpected GPT entry geometry')
            require(table_lba == (2 if here == 1 else here - 32), 'wrong GPT array location')
            disk.seek(table_lba * 512)
            table = disk.read(count * stride)
            require(len(table) == count * stride and zlib.crc32(table) == table_crc, 'GPT array CRC mismatch')
            first, last = struct.unpack_from('<QQ', table, 32)
            require(first == 2048 and last - first + 1 == filesystem_bytes // 512, 'wrong GPT region')
            require(usable_first <= first <= last <= usable_last, 'GPT region outside usable space')
            require(table[:16] == uuid.UUID(gpt_type).bytes_le and any(table[16:32]), 'wrong GPT type/identity')
            require(not any(table[stride:]), 'unexpected additional GPT partitions')
            arrays.append(table)
        require(arrays[0] == arrays[1], 'GPT copies disagree')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--target-dir', type=Path, default=Path('/data/cache/partmgr-native-partition-copy-target'))
    args = parser.parse_args()
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='partmgr-native-partition-copy-', dir='/data/cache'))
    if args.output:
        output.mkdir(parents=True, exist_ok=False)
    receipt = {'status': 'failed', 'commands': [], 'images': {},
               'scope': 'Nested fragmented-file raw GPT/MBR copy and native payload acceptance; no firmware, physical-device, container transaction or cross-layer atomicity claim',
               'source_stability': 'Caller keeps the source tree stable during build; start/end hashes detect final changes only'}
    env = dict(os.environ, LC_ALL='C', RUSTC_WRAPPER='', CARGO_TARGET_DIR=str(args.target_dir.resolve()))

    def save():
        with (output / 'receipt.json').open('w') as destination:
            json.dump(receipt, destination, indent=2)
            destination.write('\n')
            destination.flush()
            os.fsync(destination.fileno())

    def command(label, argv, acceptable=(0,)):
        result = subprocess.run(list(map(str, argv)), cwd=ROOT, env=env, capture_output=True, timeout=600)
        for stream, data in [('stdout', result.stdout), ('stderr', result.stderr)]:
            (output / f'{label}.{stream}').write_bytes(data)
        receipt['commands'].append({'label': label, 'argv': list(map(str, argv)), 'cwd': str(ROOT),
                                    'exit_code': result.returncode,
                                    'stdout_sha256': digest(output / f'{label}.stdout'),
                                    'stderr_sha256': digest(output / f'{label}.stderr')})
        save()
        require(result.returncode in acceptable, f'{label} exited {result.returncode}; retained command logs: {output}')
        return result.stdout

    try:
        tools = {}
        for name in ['cargo', 'rustc', 'cc', 'fsck.fat', 'fsck.exfat', 'fls', 'icat', 'e2fsck', 'debugfs']:
            executable = shutil.which(name)
            require(executable is not None, f'missing enabled native gate prerequisite: {name}')
            tools[name] = Path(executable).absolute()
        receipt['tool_resolved_paths'] = {name: str(path.resolve()) for name, path in tools.items()}
        inputs = [p for folder in ['src', 'examples'] for p in (ROOT / folder).rglob('*.rs')]
        inputs += [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', Path(__file__).resolve()]
        inputs += list(ROOT.glob('rust-toolchain*'))
        receipt['source_sha256'] = {str(p.relative_to(ROOT)): digest(p) for p in sorted(inputs)}
        receipt['tool_sha256'] = {str(p): digest(p) for p in tools.values()}
        retained = output / 'source'
        for path in inputs:
            copy = retained / path.relative_to(ROOT)
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, copy)
            require(digest(copy) == receipt['source_sha256'][str(path.relative_to(ROOT))], f'source changed while retaining {path}')
        for name, flags, codes in [('cargo', ['--version'], (0,)), ('rustc', ['--version'], (0,)),
                                   ('fsck.fat', ['--help'], (0, 1)), ('fsck.exfat', ['-V'], (0, 16)),
                                   ('cc', ['--version'], (0,)), ('fls', ['-V'], (0,)), ('e2fsck', ['-V'], (0,)), ('debugfs', ['-V'], (0,))]:
            command(name + '-version', [tools[name], *flags], codes)
        command('build', [tools['cargo'], 'build', '--locked', '--example', 'filesystem-fat-copy',
                          '--example', 'filesystem-exfat-copy', '--example', 'filesystem-ext-copy'])
        binaries = {}
        for family in ['fat', 'exfat', 'ext']:
            binary = args.target_dir.resolve() / 'debug/examples' / f'filesystem-{family}-copy'
            binaries[family] = output / f'{family}-copy.bin'
            shutil.copy2(binary, binaries[family])
        receipt['binary_sha256'] = {str(p): digest(p) for p in binaries.values()}
        source = output / 'source.fat'
        source.write_bytes(source_fixture())
        receipt['fixture_sha256'] = digest(source)
        command('source-fsck', [tools['fsck.fat'], '-n', source])
        basic = 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'
        linux = '0fc63daf-8483-4772-8e79-3d69d8477de4'
        for family, selector, size, typecode, gpt_type in [('fat', 12, 1440 * 1024, 1, basic), ('fat', 16, 32 << 20, 6, basic),
                                                         ('fat', 32, 64 << 20, 12, basic), ('exfat', 32, 32 << 20, 7, basic), ('ext', 16, 16 << 20, 0x83, linux)]:
            for scheme in ['gpt', 'mbr']:
                label = f'{family}{selector}-{scheme}'
                disk = output / f'{label}.img'
                argv = [binaries[family], source, 0, source.stat().st_size, disk, selector]
                if family != 'fat':
                    argv += ['--metadata-policy', 'content-only-deterministic-defaults']
                if family == 'ext':
                    argv += ['--names', 'exact-bytes']
                command(label + '-copy', [*argv, '--partition-table', scheme])
                inspect_table(disk, scheme, size, typecode, gpt_type)
                region = output / f'{label}.volume'
                with disk.open('rb') as handle, region.open('wb') as destination:
                    handle.seek(1 << 20)
                    remaining = size
                    while remaining:
                        chunk = handle.read(min(remaining, 1 << 20))
                        require(bool(chunk), 'short partition region')
                        destination.write(chunk)
                        remaining -= len(chunk)
                before = digest(region)
                native_payloads = {}
                if family == 'ext':
                    command(label + '-fsck', [tools['e2fsck'], '-fn', region])
                else:
                    command(label + '-fsck', [tools['fsck.' + family], '-n', region])
                    listing = command(label + '-fls', [tools['fls'], '-r', '-p', '-f', family, region]).decode()
                for number, (name, expected) in enumerate(payload_models().items()):
                    if family == 'ext':
                        path = native_ext_path(name)
                        payload = command(f'{label}-payload-{number}', [tools['debugfs'], '-R', f'cat "/{path}"', region])
                    else:
                        match = re.search(r'r/r\s+(\d+):\s+' + re.escape(name) + r'$', listing, re.I | re.M)
                        require(match is not None, f'payload {name} not found in native namespace: {listing}')
                        payload = command(f'{label}-payload-{number}', [tools['icat'], '-f', family, region, match.group(1)])
                    require(payload == expected, f'independent complete payload mismatch: {name}')
                    native_payloads[name] = {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
                                             'native_path': native_ext_path(name) if family == 'ext' else name}
                require(digest(region) == before, 'native check mutated extracted region')
                receipt['images'][label] = {'disk_sha256': digest(disk), 'region_sha256': before,
                                            'offset': 1 << 20, 'length': size, 'payloads': native_payloads}
                command(label + '-existing', argv, (1,))
                require(digest(disk) == receipt['images'][label]['disk_sha256'], 'existing destination changed')
                missing = output / f'{label}-invalid.img'
                argv[4] = missing
                command(label + '-invalid', [*argv, '--partition-table', 'invalid'], (1,))
                require(not missing.exists(), 'invalid table profile published output')
        receipt['source_sha256_end'] = {str(p.relative_to(ROOT)): digest(p) for p in sorted(inputs)}
        receipt['tool_sha256_end'] = {str(p): digest(p) for p in tools.values()}
        require(receipt['source_sha256_end'] == receipt['source_sha256'], 'source changed during enabled gate')
        require(receipt['tool_sha256_end'] == receipt['tool_sha256'], 'tool changed during enabled gate')
        require(digest(source) == receipt['fixture_sha256'], 'source fixture changed')
        require({str(p): digest(p) for p in binaries.values()} == receipt['binary_sha256'], 'retained executable changed')
        receipt['status'] = 'passed'
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        receipt['error'] = str(error)
    finally:
        save()
        print(f"{receipt['status']}: {output / 'receipt.json'}", flush=True)
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
