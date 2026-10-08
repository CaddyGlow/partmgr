#!/usr/bin/env python3
"""Validate audited bounded exFAT-to-FAT capture against native tools."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=Path('/data/cache/partmgr-exfat-copy-native-evidence'))
    parser.add_argument('--target-dir', type=Path,
                        default=Path('/data/cache/partmgr-filesystem-target'))
    args = parser.parse_args()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output = args.output.resolve() / f'{stamp}-{os.getpid()}'
    output.mkdir(parents=True, exist_ok=False)
    receipt = {'profile': 'audited-exfat-region-to-fat16-v1', 'status': 'running',
               'commands': [], 'tools': {}, 'capture_uses_host_extraction': False,
               'metadata_policy': 'content-only; deterministic FAT defaults',
               'source_stability': 'caller-guaranteed; final hashes do not detect transient writes',
               'layers': {'source_allocation_audit': 'pending', 'filesystem': 'pending',
                          'publication': 'pending', 'publication_directory_flush': 'pending',
                          'native_validation': 'pending', 'partition': 'standalone',
                          'container': 'raw', 'firmware_boot': 'unverified'}}
    env = dict(os.environ, LC_ALL='C', CARGO_TARGET_DIR=str(args.target_dir.resolve()))

    def save():
        with (output / 'evidence.json').open('w') as stream:
            json.dump(receipt, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())

    def command(label, argv, acceptable=(0,), must_fail=False):
        argv = [str(value) for value in argv]
        result = subprocess.run(argv, cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        log = output / (label + '.log')
        log.write_bytes(result.stdout)
        receipt['commands'].append({'label': label, 'argv': argv, 'cwd': str(ROOT),
                                    'exit_code': result.returncode, 'log': str(log),
                                    'log_sha256': digest(log)})
        save()
        if (must_fail and result.returncode == 0) or (
                not must_fail and result.returncode not in acceptable):
            raise RuntimeError(f'{label}: unexpected exit {result.returncode}; see {log}')
        return result.stdout.decode('utf-8', errors='replace')

    try:
        for name, flags in [('cargo', ['--version']), ('rustc', ['--version']),
                            ('fsck.exfat', ['-V']), ('fsck.fat', ['--help']),
                            ('mcopy', ['-V'])]:
            path = shutil.which(name)
            if path is None:
                raise RuntimeError(f'enabled native gate requires {name}')
            receipt['tools'][name] = {'path': path, 'sha256': digest(Path(path))}
            # exfatprogs 1.3.2 prints its version plus usage and exits 16 for -V.
            version_codes = (0, 1, 16) if name == 'fsck.exfat' else (0, 1)
            receipt['tools'][name]['version'] = command('version-' + name, [path, *flags], version_codes)
        fixture_dir = ROOT / 'fuzz/fixtures'
        manifest_path = fixture_dir / 'exfat-basic-prefix.json'
        manifest = json.loads(manifest_path.read_text())
        prefix_path = fixture_dir / 'exfat-basic-prefix.bin'
        if digest(prefix_path) != manifest['prefix_sha256']:
            raise RuntimeError('independent fixture prefix hash mismatch')
        archive = fixture_dir / manifest['generator_archive'].split('/')[-1]
        if digest(archive) != manifest['generator_sha256']:
            raise RuntimeError('independent fixture archived generator hash mismatch')
        prefix = prefix_path.read_bytes()
        if len(prefix) != manifest['prefix_bytes']:
            raise RuntimeError('independent fixture prefix length mismatch')
        source = output / 'source.exfat'
        source.write_bytes(prefix + bytes(manifest['logical_bytes'] - len(prefix)))
        if digest(source) != manifest['source_sha256']:
            raise RuntimeError('reconstituted source hash mismatch')
        receipt['fixture_manifest'] = manifest
        command('source-fsck', ['fsck.exfat', '-n', source])
        wrapper = output / 'bounded-source.img'
        wrapper.write_bytes(bytes([0xa5]) * 8192 + source.read_bytes() + bytes([0x5a]) * 8192)
        inputs = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', Path(__file__).resolve(),
                  ROOT / 'examples/filesystem-fat-copy.rs', manifest_path, prefix_path,
                  archive, *ROOT.glob('src/**/*.rs')]
        receipt['source_sha256'] = {str(p.relative_to(ROOT)): digest(p) for p in sorted(inputs)}
        command('build', ['cargo', 'build', '--locked', '--example', 'filesystem-fat-copy'])
        binary = args.target_dir.resolve() / 'debug/examples/filesystem-fat-copy'
        receipt['binary'] = {'path': str(binary), 'sha256': digest(binary)}
        destination = output / 'destination-fat16.img'
        source_hashes = {str(p): digest(p) for p in (source, wrapper)}
        argv = [binary, '--source-profile', 'exfat', wrapper, '8192',
                str(manifest['logical_bytes']), destination, '16']
        report = command('capture', argv)
        for marker in ('source_allocation_audit=complete', 'reopened_audit=complete',
                       'publication=completed', 'publication_directory_flush=complete'):
            if marker not in report:
                raise RuntimeError('capture missing stage marker: ' + marker)
        receipt['layers'].update(source_allocation_audit='complete', filesystem='verified',
                                 publication='completed', publication_directory_flush='complete')
        image_hash = digest(destination)
        command('destination-fsck', ['fsck.fat', '-n', '-v', destination])
        expected = {'prefixNoChain.bin': bytes((i * 17 + 3) % 251 for i in range(600)) + bytes(100),
                    'CHAIN.BIN': bytes((i * 13 + 9) % 251 for i in range(900)),
                    'nested/inside': b'child'}
        receipt['payloads'] = []
        for index, (name, data) in enumerate(expected.items()):
            extracted = output / f'payload-{index}.bin'
            command('extract-' + str(index), ['mcopy', '-i', destination, '::/' + name, extracted])
            if extracted.read_bytes() != data:
                raise RuntimeError('payload mismatch: ' + name)
            receipt['payloads'].append({'name': name, 'bytes': len(data), 'sha256': digest(extracted)})
        refusal = command('existing-destination', argv, must_fail=True)
        if 'exist' not in refusal:
            raise RuntimeError('missing existing-destination diagnostic')
        # Independent fixture layout: bitmap at cluster 3, cluster 12 is initially free.
        damaged = bytearray(source.read_bytes())
        sector = 1 << damaged[108]
        cluster_bytes = sector << damaged[109]
        heap = int.from_bytes(damaged[88:92], 'little') * sector
        bitmap = heap + cluster_bytes
        if damaged[bitmap + 1] & 4:
            raise RuntimeError('fixture cluster 12 unexpectedly allocated')
        damaged[bitmap + 1] |= 4
        damaged_source = output / 'lost-allocation.exfat'
        damaged_source.write_bytes(damaged)
        bad_destination = output / 'must-not-publish.img'
        bad_hash = digest(damaged_source)
        rejection = command('lost-allocation-refusal', [binary, '--source-profile', 'exfat',
                            damaged_source, '0', str(len(damaged)), bad_destination, '16'], must_fail=True)
        if 'ownership/state audit failed' not in rejection or bad_destination.exists():
            raise RuntimeError('malformed source not rejected before publication')
        if digest(damaged_source) != bad_hash:
            raise RuntimeError('damaged source changed')
        if {str(p): digest(p) for p in (source, wrapper)} != source_hashes or digest(destination) != image_hash:
            raise RuntimeError('source or destination changed during validation/refusal')
        receipt.update(status='passed', unchanged_source_sha256=source_hashes,
                       destination_sha256=image_hash, existing_destination_refused=True,
                       lost_allocation_refused_before_output=True, valid_data_zero_tail_bytes=100)
        receipt['layers']['native_validation'] = 'passed'
        save()
        fd = os.open(output, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        print(output / 'evidence.json')
        return 0
    except Exception as error:
        receipt.update(status='failed', reason=str(error))
        save()
        print(output / 'evidence.json')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
