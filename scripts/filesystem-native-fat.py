#!/usr/bin/env python3
"""Validate read-only FAT streaming against dosfstools and mtools images."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def root_entry(image, family, name):
    """Read the known first-root-cluster short entry without partmgr code."""
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
        entries = source.read(length)
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
    receipt = {'status': 'running', 'scope': 'FAT12/16/32 known root short-entry reading and deterministic root-file image authoring',
               'tools': {}, 'commands': [], 'profiles': [],
               'sources': {str(p.relative_to(ROOT)): digest(p) for p in
                           sorted([ROOT / 'Cargo.toml', ROOT / 'Cargo.lock',
                                   Path(__file__).resolve(),
                                   ROOT / 'examples/filesystem-fat-inspect.rs',
                                   ROOT / 'examples/filesystem-fat-build.rs'] +
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
        missing = [tool for tool in ('mkfs.fat', 'fsck.fat', 'mcopy', 'mdir', 'cargo')
                   if not shutil.which(tool)]
        if missing:
            receipt.update(status='skipped', missing_tools=missing)
            save()
            print(f'SKIPPED: missing {missing}; evidence: {output}')
            return 77
        for tool, option in [('mkfs.fat', '--help'), ('fsck.fat', '--help'),
                             ('mcopy', '-V'), ('mdir', '-V'), ('cargo', '--version')]:
            receipt['tools'][tool] = {'path': shutil.which(tool),
                                     'version_output': run([tool, option], f'version-{tool}', False)}
        run(['cargo', 'build', '--locked', '--example', 'filesystem-fat-inspect',
             '--example', 'filesystem-fat-build',
             '--target-dir', str(args.target_dir)], 'cargo-build')
        binary = args.target_dir.resolve() / 'debug/examples/filesystem-fat-inspect'
        builder = args.target_dir.resolve() / 'debug/examples/filesystem-fat-build'
        receipt['binary_sha256'] = digest(binary)
        receipt['builder_binary_sha256'] = digest(builder)
        # Multiple clusters and a non-aligned tail, independently generated bytes.
        payload = output / 'PAYLOAD.BIN'
        payload.write_bytes(bytes((i * 37 + i // 251 + 19) % 256 for i in range(131089)))
        expected = digest(payload)
        for family, blocks in [(12, 1440), (16, 32768), (32, 131072)]:
            image = output / f'fat{family}.img'
            run(['mkfs.fat', '--invariant', '-F', str(family), '-C', str(image),
                 str(blocks)], f'fat{family}-mkfs')
            run(['mcopy', '-i', str(image), str(payload), '::PAYLOAD.BIN'], f'fat{family}-mcopy')
            before = digest(image)
            run(['mdir', '-i', str(image), '::'], f'fat{family}-mdir')
            fsck_output = run(['fsck.fat', '-n', '-v', str(image)], f'fat{family}-fsck')
            receipt['tools']['fsck.fat']['version'] = fsck_output.splitlines()[0]
            cluster, size = root_entry(image, family, b'PAYLOAD BIN')
            streamed = output / f'fat{family}-streamed.bin'
            inspection = run([str(binary), str(image), str(cluster), str(size), str(streamed)],
                             f'fat{family}-inspect')
            actual = digest(streamed)
            after = digest(image)
            row = {'operation': 'native-created-reader', 'family': family, 'image': str(image), 'first_cluster': cluster,
                   'directory_size': size, 'expected_size': payload.stat().st_size,
                   'expected_sha256': expected, 'streamed_sha256': actual,
                   'image_sha256_before_read_checks': before,
                   'image_sha256_after_read_checks': after,
                   'passed': size == payload.stat().st_size and actual == expected and
                   before == after and f'family=Fat{family} ' in inspection}
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
            row = {'operation': 'partmgr-authored-native-validation', 'family': family,
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
