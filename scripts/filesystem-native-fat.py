#!/usr/bin/env python3
"""Validate FAT streaming and image authoring with dosfstools and mtools."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def root_bytes(image, family):
    """Read the fixed root or first FAT32 root cluster without partmgr code."""
    with image.open('rb') as source:
        boot = source.read(512)
        sector = struct.unpack_from('<H', boot, 11)[0]
        sectors_per_cluster = boot[13]
        reserved = struct.unpack_from('<H', boot, 14)[0]
        fats = boot[16]
        root_count = struct.unpack_from('<H', boot, 17)[0]
        fat_sectors = struct.unpack_from('<H', boot, 22)[0]
        if family == 32:
            fat_sectors = struct.unpack_from('<I', boot, 36)[0]
            root_cluster = struct.unpack_from('<I', boot, 44)[0]
            offset = (reserved + fats * fat_sectors +
                      (root_cluster - 2) * sectors_per_cluster) * sector
            length = sectors_per_cluster * sector
        else:
            offset = (reserved + fats * fat_sectors) * sector
            length = root_count * 32
        source.seek(offset)
        return source.read(length)


def root_entry(image, family, name):
    entries = root_bytes(image, family)
    matches = []
    for index in range(0, len(entries), 32):
        entry = entries[index:index + 32]
        if len(entry) != 32 or entry[0] == 0:
            break
        if entry[0] == 0xE5 or entry[11] == 0x0F:
            continue
        if entry[:11] == name and not entry[11] & 0x18:
            cluster = struct.unpack_from('<H', entry, 26)[0]
            if family == 32:
                cluster |= struct.unpack_from('<H', entry, 20)[0] << 16
            matches.append((cluster, struct.unpack_from('<I', entry, 28)[0]))
    if len(matches) != 1:
        raise ValueError(f'expected one root short entry, found {len(matches)}')
    return matches[0]


def long_root_entry(image, family, name):
    """Locate a known externally inserted LFN by validating its preceding slots."""
    entries = root_bytes(image, family)
    pending = []
    matches = []
    for offset in range(0, len(entries), 32):
        entry = entries[offset:offset + 32]
        if len(entry) != 32 or entry[0] == 0:
            break
        if entry[0] == 0xE5:
            pending = []
            continue
        if entry[11] == 0x0F:
            pending.append(entry)
            continue
        if pending and not entry[11] & 0x18:
            count = len(pending)
            checksum = 0
            for byte in entry[:11]:
                checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 255
            for index, slot in enumerate(pending):
                expected_ordinal = count - index | (0x40 if index == 0 else 0)
                if (slot[0] != expected_ordinal or slot[12] != 0 or
                        slot[13] != checksum or slot[26:28] != b'\0\0'):
                    raise ValueError('invalid external fixture LFN sequence')
            units = []
            for slot in reversed(pending):
                for start in (1, 14, 28):
                    length = {1: 10, 14: 12, 28: 4}[start]
                    units.extend(struct.unpack('<' + 'H' * (length // 2), slot[start:start + length]))
            if 0 in units:
                terminator = units.index(0)
                if any(unit != 0xFFFF for unit in units[terminator + 1:]):
                    raise ValueError('invalid external fixture LFN padding')
                units = units[:terminator]
            decoded = struct.pack('<' + 'H' * len(units), *units).decode('utf-16le')
            if decoded == name:
                cluster = struct.unpack_from('<H', entry, 26)[0]
                if family == 32:
                    cluster |= struct.unpack_from('<H', entry, 20)[0] << 16
                matches.append((cluster, struct.unpack_from('<I', entry, 28)[0], entry[:11].hex()))
        pending = []
    if len(matches) != 1:
        raise ValueError(f'expected one root LFN entry, found {len(matches)}')
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=Path('/data/cache/partmgr-filesystem-native-evidence'))
    parser.add_argument('--target-dir', type=Path,
                        default=Path('/data/cache/partmgr-native-fat-target'))
    args = parser.parse_args()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output = args.output.resolve() / f'{stamp}-{os.getpid()}'
    output.mkdir(parents=True, exist_ok=False)
    receipt = {'schema_version': 2, 'evidence_version': 'fat-native-v2', 'status': 'running', 'scope': 'FAT12/16/32 native root-file reading and deterministic root-file plus nested EFI-shaped VFAT tree authoring',
               'python_version': sys.version, 'tools': {}, 'commands': [], 'profiles': [],
               'sources': {str(p.relative_to(ROOT)): digest(p) for p in
                           sorted([ROOT / 'Cargo.toml', ROOT / 'Cargo.lock',
                                   Path(__file__).resolve(),
                                   ROOT / 'examples/filesystem-fat-inspect.rs',
                                   ROOT / 'examples/filesystem-fat-build.rs',
                                   ROOT / 'examples/filesystem-fat-build-tree.rs'] +
                                  list((ROOT / 'src').rglob('*.rs')))}}

    def save():
        (output / 'evidence.json').write_text(json.dumps(receipt, indent=2) + '\n')

    def run(command, label, checked=True):
        log = output / f'{label}.log'
        with log.open('w') as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream,
                                    stderr=subprocess.STDOUT, env=dict(os.environ, LC_ALL='C'))
        receipt['commands'].append({'argv': list(map(str, command)),
                                    'exit_code': result.returncode, 'log': str(log)})
        save()
        if checked and result.returncode:
            raise RuntimeError(f'{label} failed with exit {result.returncode}')
        return log.read_text(errors='replace')

    try:
        missing = [tool for tool in ('mkfs.fat', 'fsck.fat', 'mcopy', 'mdir', 'cargo', 'rustc')
                   if not shutil.which(tool)]
        if missing:
            receipt.update(status='skipped', missing_tools=missing)
            save()
            print(f'SKIPPED: missing {missing}; evidence: {output}')
            return 77
        for tool, option in [('mkfs.fat', '--help'), ('fsck.fat', '--help'),
                             ('mcopy', '-V'), ('mdir', '-V'), ('cargo', '--version'),
                             ('rustc', '--version')]:
            receipt['tools'][tool] = {'path': shutil.which(tool),
                                     'version_output': run([tool, option], f'version-{tool}', False)}
        run(['cargo', 'build', '--locked', '--example', 'filesystem-fat-inspect',
             '--example', 'filesystem-fat-build', '--example', 'filesystem-fat-build-tree',
             '--target-dir', str(args.target_dir)], 'cargo-build')
        binary = args.target_dir.resolve() / 'debug/examples/filesystem-fat-inspect'
        builder = args.target_dir.resolve() / 'debug/examples/filesystem-fat-build'
        receipt['binary_sha256'] = digest(binary)
        receipt['builder_binary_sha256'] = digest(builder)
        tree_builder = args.target_dir.resolve() / 'debug/examples/filesystem-fat-build-tree'
        receipt['tree_builder_binary_sha256'] = digest(tree_builder)
        # Multiple clusters and a non-aligned tail, independently generated bytes.
        payload = output / 'PAYLOAD.BIN'
        payload.write_bytes(bytes((i * 37 + i // 251 + 19) % 256 for i in range(131089)))
        expected = digest(payload)
        long_name = 'Long payload name.txt'
        long_name_hex = long_name.encode('utf-16le').hex()
        for family, blocks in [(12, 1440), (16, 32768), (32, 131072)]:
            image = output / f'fat{family}.img'
            run(['mkfs.fat', '--invariant', '-F', str(family), '-C', str(image),
                 str(blocks)], f'fat{family}-mkfs')
            run(['mcopy', '-i', str(image), str(payload), '::PAYLOAD.BIN'], f'fat{family}-mcopy')
            run(['mcopy', '-i', str(image), str(payload), f'::{long_name}'],
                f'fat{family}-mcopy-long-name')
            before = digest(image)
            run(['mdir', '-i', str(image), '::'], f'fat{family}-mdir')
            fsck_output = run(['fsck.fat', '-n', '-v', str(image)], f'fat{family}-fsck')
            receipt['tools']['fsck.fat']['version'] = fsck_output.splitlines()[0]
            cluster, size = root_entry(image, family, b'PAYLOAD BIN')
            streamed = output / f'fat{family}-streamed.bin'
            inspection = run([str(binary), str(image), str(cluster), str(size), str(streamed)],
                             f'fat{family}-inspect')
            actual = digest(streamed)
            listing = run([str(binary), str(image), '--list'], f'fat{family}-list')
            name_matches = sum('native_name=utf16' in line.split() and
                               f'name_hex={long_name_hex}' in line.split()
                               for line in listing.splitlines())
            long_cluster, long_size, long_short_hex = long_root_entry(image, family, long_name)
            long_streamed = output / f'fat{family}-long-name-streamed.bin'
            run([str(binary), str(image), str(long_cluster), str(long_size), str(long_streamed)],
                f'fat{family}-long-name-inspect')
            long_actual = digest(long_streamed)
            after = digest(image)
            row = {'operation': 'native-created-reader', 'profile_version': 'native-root-reader-v1', 'family': family, 'image': str(image), 'first_cluster': cluster,
                   'directory_size': size, 'expected_size': payload.stat().st_size,
                   'expected_sha256': expected, 'streamed_sha256': actual,
                   'lfn': {'name': long_name, 'expected_utf16le_hex': long_name_hex,
                           'listed_exact_name_count': name_matches,
                           'independent_short_name_hex': long_short_hex,
                           'first_cluster': long_cluster, 'directory_size': long_size,
                           'expected_sha256': expected, 'streamed_sha256': long_actual},
                   'image_sha256_before_read_checks': before,
                   'image_sha256_after_read_checks': after,
                   'passed': size == payload.stat().st_size and actual == expected and
                   before == after and f'family=Fat{family} ' in inspection and
                   name_matches == 1 and long_size == payload.stat().st_size and
                   long_actual == expected}
            receipt['profiles'].append(row)
            save()
            if not row['passed']:
                raise RuntimeError(f'FAT{family} content, family, or image immutability mismatch')
        for family in (12, 16, 32):
            image = output / f'authored-fat{family}.img'
            repeated = output / f'authored-fat{family}-repeat.img'
            for path, suffix in ((image, ''), (repeated, '-repeat')):
                run([str(builder), str(path), str(family), str(payload)],
                    f'authored-fat{family}-build{suffix}')
            before = digest(image)
            repeated_hash = digest(repeated)
            run(['mdir', '-i', str(image), '::'], f'authored-fat{family}-mdir')
            run(['fsck.fat', '-n', '-v', str(image)], f'authored-fat{family}-fsck')
            extracted = output / f'authored-fat{family}-extracted.bin'
            run(['mcopy', '-i', str(image), '::PAYLOAD.BIN', str(extracted)],
                f'authored-fat{family}-extract')
            actual = digest(extracted)
            after = digest(image)
            cluster, size = root_entry(image, family, b'PAYLOAD BIN')
            row = {'operation': 'partmgr-authored-native-validation', 'profile_version': 'root-short-builder-v1', 'family': family,
                   'image': str(image), 'repeated_image': str(repeated),
                   'first_cluster': cluster, 'directory_size': size,
                   'expected_size': payload.stat().st_size,
                   'expected_sha256': expected, 'extracted_sha256': actual,
                   'image_sha256_before_read_checks': before,
                   'image_sha256_after_read_checks': after,
                   'repeated_image_sha256': repeated_hash,
                   'passed': size == payload.stat().st_size and actual == expected and
                   before == after == repeated_hash}
            receipt['profiles'].append(row)
            save()
            if not row['passed']:
                raise RuntimeError(f'authored FAT{family} content, determinism, or immutability mismatch')
        nested_names = ['BOOTX64.EFI',
                        'Long boot payload sharing prefix alpha.txt',
                        'Long boot payload sharing prefix beta.txt',
                        'Long boot payload sharing prefix gamma.txt',
                        '123456789.txt']
        for family in (12, 16, 32):
            image = output / f'tree-fat{family}.img'
            repeated = output / f'tree-fat{family}-reverse.img'
            for path, order in ((image, 'forward'), (repeated, 'reverse')):
                run([str(tree_builder), str(path), str(family), str(payload), order],
                    f'tree-fat{family}-build-{order}')
            before = digest(image)
            repeated_hash = digest(repeated)
            run(['fsck.fat', '-n', '-v', str(image)], f'tree-fat{family}-fsck')
            run(['mdir', '-i', str(image), '::'], f'tree-fat{family}-root-mdir')
            run(['mdir', '-i', str(image), '::EFI/BOOT'], f'tree-fat{family}-boot-mdir')
            extracted_files = []
            for index, name in enumerate(nested_names):
                extracted = output / f'tree-fat{family}-nested-{index}.bin'
                run(['mcopy', '-i', str(image), f'::EFI/BOOT/{name}', str(extracted)],
                    f'tree-fat{family}-extract-{index}')
                extracted_files.append({'path': f'EFI/BOOT/{name}',
                                        'native_utf16le_hex': name.encode('utf-16le').hex(),
                                        'size': extracted.stat().st_size,
                                        'sha256': digest(extracted)})
            empty = output / f'tree-fat{family}-empty.bin'
            run(['mcopy', '-i', str(image), '::ROOT019', str(empty)],
                f'tree-fat{family}-extract-empty')
            after = digest(image)
            row = {'operation': 'partmgr-authored-native-tree-validation',
                   'profile_version': 'efi-shaped-tree-v1', 'family': family,
                   'metadata_policy': 'deterministic-defaults',
                   'namespace_policy': 'ascii-fold-exact-other-utf16',
                   'image': str(image), 'reversed_inventory_image': str(repeated),
                   'expected_size': payload.stat().st_size, 'expected_sha256': expected,
                   'nested_files': extracted_files, 'root_empty_size': empty.stat().st_size,
                   'image_sha256_before_read_checks': before,
                   'image_sha256_after_read_checks': after,
                   'reversed_inventory_image_sha256': repeated_hash,
                   'passed': before == after == repeated_hash and empty.stat().st_size == 0 and
                   all(file['size'] == payload.stat().st_size and file['sha256'] == expected
                       for file in extracted_files)}
            receipt['profiles'].append(row)
            save()
            if not row['passed']:
                raise RuntimeError(f'tree FAT{family} nested content or deterministic image mismatch')
        receipt['status'] = 'passed'
        save()
        print(f'PASSED: FAT12/16/32; evidence: {output}')
        return 0
    except Exception as error:
        receipt.update(status='failed', error=str(error))
        save()
        print(f'FAILED: {error}; evidence: {output}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
